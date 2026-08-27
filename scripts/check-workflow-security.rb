#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path("..", __dir__)

class WorkflowError < StandardError; end

def require_gate(condition, message)
  raise WorkflowError, message unless condition
end

def load_workflow(path)
  value = YAML.safe_load(File.read(path), aliases: true)
  require_gate(value.is_a?(Hash), "workflow_invalid")
  value
rescue Psych::Exception, Errno::ENOENT
  raise WorkflowError, "workflow_invalid"
end

def job!(workflow, name)
  jobs = workflow["jobs"]
  require_gate(jobs.is_a?(Hash), "workflow_jobs_invalid")
  job = jobs[name]
  require_gate(job.is_a?(Hash), "workflow_job_missing:#{name}")
  steps = job["steps"]
  require_gate(steps.is_a?(Array), "workflow_steps_invalid:#{name}")
  job
end

def step!(job, name)
  matches = job.fetch("steps").select { |step| step.is_a?(Hash) && step["name"] == name }
  require_gate(matches.length == 1, "workflow_step_missing_or_duplicate:#{name}")
  matches.first
end

def active_step!(job, name)
  step = step!(job, name)
  require_gate(!step.key?("if"), "workflow_step_conditional:#{name}")
  require_gate(step["continue-on-error"] != true, "workflow_step_nonblocking:#{name}")
  require_gate(step["run"].is_a?(String), "workflow_step_has_no_command:#{name}")
  step
end

# JANUS-438: a small number of steps are deliberately conditional (the
# go-only PR bypass for Rust engine assurance and Nix). Pin the exact
# condition text so the gate cannot be silently loosened or removed while
# still calling itself "conditional".
def conditional_step!(job, name, expected_if)
  step = step!(job, name)
  require_gate(step["if"] == expected_if, "workflow_step_condition_mismatch:#{name}")
  require_gate(step["continue-on-error"] != true, "workflow_step_nonblocking:#{name}")
  require_gate(step["run"].is_a?(String), "workflow_step_has_no_command:#{name}")
  step
end

def action!(job, repository)
  prefix = "#{repository}@"
  matches = job.fetch("steps").select do |step|
    step.is_a?(Hash) && step["uses"].is_a?(String) && step["uses"].start_with?(prefix)
  end
  require_gate(matches.length == 1, "workflow_action_missing_or_duplicate:#{repository}")
  matches.first
end

def command_lines(step)
  step.fetch("run").lines.map(&:strip).reject do |line|
    line.empty? || line.start_with?("#")
  end
end

def command!(step, fragment)
  require_gate(
    command_lines(step).any? { |line| line.include?(fragment) },
    "workflow_command_missing:#{fragment}"
  )
end

def environment!(step, name, expected)
  environment = step["env"]
  require_gate(environment.is_a?(Hash), "workflow_environment_missing:#{name}")
  require_gate(
    environment[name] == expected,
    "workflow_environment_mismatch:#{name}"
  )
end

def before!(job, first_name, second_name)
  names = job.fetch("steps").map { |step| step.is_a?(Hash) ? step["name"] : nil }
  first = names.index(first_name)
  second = names.index(second_name)
  require_gate(first && second && first < second, "workflow_step_order:#{first_name}:#{second_name}")
end

def validate(workflows)
  go_check = job!(workflows.fetch(:go), "build-test")
  go_source_verify = active_step!(go_check, "verify installed source scanner versions")
  command!(go_source_verify, "--tool gitleaks --tool govulncheck --tool staticcheck")
  active_step!(go_check, "staticcheck")
  active_step!(go_check, "govulncheck")
  active_step!(go_check, "Gitleaks history and negative fixture")
  go_image_verify = active_step!(go_check, "verify installed image scanner version")
  command!(go_image_verify, "--tool trivy")
  active_step!(go_check, "build and scan local candidate image")
  before!(go_check, "verify installed source scanner versions", "staticcheck")
  before!(go_check, "verify installed source scanner versions", "govulncheck")
  before!(go_check, "verify installed source scanner versions", "Gitleaks history and negative fixture")
  before!(go_check, "verify installed image scanner version", "build and scan local candidate image")

  go_image = job!(workflows.fetch(:go), "image")
  active_step!(go_image, "verify protected-main release ancestry")
  active_step!(go_image, "verify installed release scanner version")
  go_published_scan = active_step!(go_image, "scan exact published candidate digest")
  command!(go_published_scan, '--subject "${IMAGE}@${{ steps.build.outputs.digest }}"')
  before!(go_image, "verify protected-main release ancestry", "scan exact published candidate digest")
  before!(go_image, "verify installed release scanner version", "scan exact published candidate digest")

  rust_fast = job!(workflows.fetch(:rust), "check-fast")
  rust_dependency_verify = active_step!(rust_fast, "verify installed dependency scanner versions")
  command!(rust_dependency_verify, "--tool cargo-audit --tool gitleaks")
  policy = active_step!(rust_fast, "release security policy and negative fixtures")
  command!(policy, "scripts/check-native-release-set.py --self-test")
  command!(policy, "scripts/report-rust-release-timing.py --self-test")
  command!(policy, "scripts/classify-pr-paths.py --self-test")
  command!(policy, "scripts/check-engine-assurance-inventory.py --self-test")
  command!(policy, "scripts/report-pr-critical-path.py --self-test")
  before!(rust_fast, "verify installed dependency scanner versions", "release security policy and negative fixtures")

  # JANUS-438: classify + the go-only bypass on check-nix and the split
  # engine-assurance jobs. The run/skip conditions are pinned exactly so a
  # future edit cannot silently widen the bypass or drop a required check.
  go_only_run_condition = "needs.classify.result != 'success' || needs.classify.outputs.go_only != 'true'"
  go_only_skip_condition = "needs.classify.result == 'success' && needs.classify.outputs.go_only == 'true'"

  rust_classify = job!(workflows.fetch(:rust), "classify")
  require_gate(rust_classify["if"] == "github.event_name == 'pull_request'", "rust_classify_trigger_invalid")
  classify_checkout = action!(rust_classify, "actions/checkout")
  require_gate(classify_checkout.dig("with", "fetch-depth") == 0, "rust_classify_checkout_depth_invalid")
  classify_step = active_step!(rust_classify, "classify changed paths")
  require_gate(
    command_lines(classify_step) == [
      'python3 scripts/classify-pr-paths.py --base "${BASE_SHA}" --head "${HEAD_SHA}" --github-output "${GITHUB_OUTPUT}"'
    ],
    "rust_classify_command_invalid"
  )
  environment!(classify_step, "BASE_SHA", "${{ github.event.pull_request.base.sha }}")
  environment!(classify_step, "HEAD_SHA", "${{ github.event.pull_request.head.sha }}")

  rust_nix = job!(workflows.fetch(:rust), "check-nix")
  require_gate(rust_nix["needs"] == "classify", "rust_nix_missing_classify_dependency")
  require_gate(rust_nix["if"] == "always() && !cancelled()", "rust_nix_job_condition_invalid")
  nix_step = conditional_step!(rust_nix, "nix package", go_only_run_condition)
  command!(nix_step, "nix build .#janus-engine")
  conditional_step!(rust_nix, "nix package not applicable (go-only change)", go_only_skip_condition)

  rust_assurance_tests = job!(workflows.fetch(:rust), "check-assurance-tests")
  require_gate(rust_assurance_tests["needs"] == "classify", "rust_assurance_tests_missing_classify_dependency")
  require_gate(
    rust_assurance_tests["if"] == "always() && !cancelled()",
    "rust_assurance_tests_job_condition_invalid"
  )
  assurance_tests_step =
    conditional_step!(rust_assurance_tests, "engine release assurance gate (tests)", go_only_run_condition)
  command!(assurance_tests_step, "scripts/assure-engine-release.sh --phase tests")
  environment!(assurance_tests_step, "JANUS_ENGINE_SMOKE_IMAGE", "janus-engine:minimization")
  environment!(assurance_tests_step, "JANUS_ENGINE_SMOKE_SKIP_BUILD", "true")
  minimization_build = step!(rust_assurance_tests, "build cache-backed minimization candidate")
  require_gate(minimization_build["if"] == go_only_run_condition, "rust_minimization_build_condition_invalid")
  require_gate(
    minimization_build["uses"] ==
      "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
    "rust_minimization_build_action_invalid"
  )
  require_gate(
    minimization_build.dig("with", "tags") == "janus-engine:minimization",
    "rust_minimization_build_tag_invalid"
  )
  require_gate(minimization_build.dig("with", "context") == ".", "rust_minimization_context_invalid")
  require_gate(
    minimization_build.dig("with", "file") == "Dockerfile.engine",
    "rust_minimization_dockerfile_invalid"
  )
  require_gate(
    minimization_build.dig("with", "platforms") == "linux/amd64",
    "rust_minimization_platform_invalid"
  )
  require_gate(minimization_build.dig("with", "load") == true, "rust_minimization_load_invalid")
  require_gate(
    minimization_build.dig("with", "cache-from") == "type=gha,scope=rust-engine-linux-amd64",
    "rust_minimization_cache_source_invalid"
  )
  conditional_step!(
    rust_assurance_tests,
    "engine release assurance gate (tests) not applicable (go-only change)",
    go_only_skip_condition
  )

  rust_assurance_smoke = job!(workflows.fetch(:rust), "check-assurance-smoke")
  require_gate(rust_assurance_smoke["needs"] == "classify", "rust_assurance_smoke_missing_classify_dependency")
  require_gate(
    rust_assurance_smoke["if"] == "always() && !cancelled()",
    "rust_assurance_smoke_job_condition_invalid"
  )
  assurance_smoke_step =
    conditional_step!(rust_assurance_smoke, "engine release assurance gate (smoke)", go_only_run_condition)
  command!(assurance_smoke_step, "scripts/assure-engine-release.sh --phase smoke")
  conditional_step!(
    rust_assurance_smoke,
    "engine release assurance gate (smoke) not applicable (go-only change)",
    go_only_skip_condition
  )

  rust_assurance = job!(workflows.fetch(:rust), "check-assurance")
  require_gate(rust_assurance["if"] == "always()", "rust_assurance_job_condition_invalid")
  require_gate(
    rust_assurance["needs"] == %w[check-assurance-tests check-assurance-smoke],
    "rust_assurance_fan_in_missing_needs"
  )
  fan_in = active_step!(rust_assurance, "require both engine assurance proof families")
  command!(fan_in, 'test "${TESTS}" = success')
  command!(fan_in, 'test "${SMOKE}" = success')
  inventory = active_step!(rust_assurance, "verify engine assurance phase inventory")
  command!(inventory, "scripts/check-engine-assurance-inventory.py")

  rust_aggregate = job!(workflows.fetch(:rust), "check")
  require_gate(rust_aggregate["if"] == "always()", "rust_aggregate_job_condition_invalid")
  require_gate(
    rust_aggregate["needs"] == %w[check-fast check-nix check-assurance image-amd64 image-arm64],
    "rust_aggregate_missing_needs"
  )
  active_step!(rust_aggregate, "require every Rust assurance boundary")

  rust_amd64 = job!(workflows.fetch(:rust), "image-amd64")
  rust_arm64 = job!(workflows.fetch(:rust), "image-arm64")
  require_gate(rust_amd64["runs-on"] == "ubuntu-24.04", "rust_amd64_runner_not_native")
  require_gate(rust_arm64["runs-on"] == "ubuntu-24.04-arm", "rust_arm64_runner_not_native")
  active_step!(rust_arm64, "verify native arm64 runner")
  step!(rust_amd64, "build native amd64 image")
  step!(rust_arm64, "build native arm64 image")
  amd64_smoke = step!(rust_amd64, "smoke native amd64 candidate")
  arm64_smoke = step!(rust_arm64, "smoke native arm64 candidate")
  [amd64_smoke, arm64_smoke].each do |smoke|
    require_gate(smoke["if"] == "github.event_name != 'release'", "rust_native_smoke_condition_invalid")
    require_gate(smoke["continue-on-error"] != true, "rust_native_smoke_nonblocking")
    require_gate(smoke["run"] == "scripts/smoke-engine-container.sh", "rust_native_smoke_invalid")
    require_gate(smoke.dig("env", "JANUS_ENGINE_SMOKE_SKIP_BUILD") == "true",
                 "rust_native_smoke_rebuilds")
  end
  require_gate(
    !workflows.fetch(:rust).inspect.include?("docker/setup-qemu-action"),
    "rust_release_qemu_returned"
  )

  rust_image = job!(workflows.fetch(:rust), "image")
  active_step!(rust_image, "verify protected-main release ancestry")
  active_step!(rust_image, "verify installed release scanner version")
  rust_published_scan = active_step!(rust_image, "scan exact published candidate digest")
  command!(rust_published_scan, '--subject "${IMAGE}@${{ steps.manifest.outputs.digest }}"')
  rust_mode_receipts =
    active_step!(rust_image, "verify published engine digest and mode receipts")
  environment!(rust_mode_receipts, "JANUS_PRODUCT_MODE", "production")
  environment!(rust_mode_receipts, "JANUS_PREVIOUS_PRODUCT_MODE", "production")
  environment!(
    rust_mode_receipts,
    "JANUS_PUBLISHED_ENGINE_ADMISSION_RECEIPT",
    "rust-engine-admission.json"
  )
  command!(rust_mode_receipts, "scripts/smoke-published-engine.sh")
  command!(rust_mode_receipts, "--mode enterprise")
  command!(rust_mode_receipts, "--previous-mode enterprise")
  command!(rust_mode_receipts, "--output rust-engine-admission-enterprise.json")
  command!(rust_mode_receipts, "scripts/check-release-mode-receipts.py")
  rust_upload = active_step!(rust_image, "upload mode-specific admission receipts")
  command!(rust_upload, "rust-engine-admission.json")
  command!(rust_upload, "rust-engine-admission-enterprise.json")
  before!(rust_image, "verify protected-main release ancestry", "scan exact published candidate digest")
  before!(rust_image, "verify installed release scanner version", "scan exact published candidate digest")
  before!(
    rust_image,
    "scan exact published candidate digest",
    "verify published engine digest and mode receipts"
  )
  before!(
    rust_image,
    "verify published engine digest and mode receipts",
    "upload mode-specific admission receipts"
  )
  rust_timing = job!(workflows.fetch(:rust), "release-timing")
  timing = active_step!(rust_timing, "measure and enforce release latency")
  command!(timing, "for attempt in {1..6}")
  command!(timing, 'test "${image_conclusion}" = success')

  gitleaks = job!(workflows.fetch(:security), "gitleaks")
  gitleaks_verify = active_step!(gitleaks, "verify installed scanner version")
  command!(gitleaks_verify, "--check-installed-tools --tool gitleaks")
  active_step!(gitleaks, "scan history and prove the negative fixture")
  before!(gitleaks, "verify installed scanner version", "scan history and prove the negative fixture")

  rehearsal_workflow = workflows.fetch(:rehearsal)
  require_gate(
    rehearsal_workflow[true] == { "workflow_dispatch" => nil },
    "release_rehearsal_trigger_invalid"
  )
  require_gate(
    rehearsal_workflow["permissions"] == { "contents" => "read", "packages" => "read" },
    "release_rehearsal_permissions_invalid"
  )
  rehearsal = job!(rehearsal_workflow, "rehearse-release-tools")
  require_gate(!rehearsal.key?("permissions"), "release_rehearsal_job_permissions_override")
  require_gate(rehearsal["timeout-minutes"] == 15, "release_rehearsal_timeout_invalid")

  ["docker/setup-buildx-action", "docker/login-action", "docker/metadata-action",
   "aquasecurity/setup-trivy", "sigstore/cosign-installer"].each do |repository|
    require_gate(
      action!(go_image, repository)["uses"] == action!(rust_image, repository)["uses"],
      "release_action_drift:#{repository}"
    )
  end

  {
    "actions/checkout" => action!(rust_fast, "actions/checkout")["uses"],
    "docker/setup-buildx-action" => action!(rust_image, "docker/setup-buildx-action")["uses"],
    "docker/login-action" => action!(rust_image, "docker/login-action")["uses"],
    "docker/metadata-action" => action!(rust_image, "docker/metadata-action")["uses"],
    "aquasecurity/setup-trivy" => action!(rust_image, "aquasecurity/setup-trivy")["uses"],
    "sigstore/cosign-installer" => action!(rust_image, "sigstore/cosign-installer")["uses"]
  }.each do |repository, expected|
    require_gate(
      action!(rehearsal, repository)["uses"] == expected,
      "release_rehearsal_action_drift:#{repository}"
    )
  end

  login = action!(rehearsal, "docker/login-action")
  require_gate(
    login["with"] == {
      "registry" => "ghcr.io",
      "username" => "${{ github.actor }}",
      "password" => "${{ secrets.GITHUB_TOKEN }}"
    },
    "release_rehearsal_login_invalid"
  )
  metadata = action!(rehearsal, "docker/metadata-action")
  require_gate(
    metadata["with"] == {
      "images" => "ghcr.io/${{ github.repository }}/release-rehearsal",
      "tags" => "type=raw,value=rehearsal"
    },
    "release_rehearsal_metadata_invalid"
  )

  strategy = rehearsal["strategy"]
  require_gate(strategy.is_a?(Hash), "release_rehearsal_matrix_missing")
  include_rows = strategy.dig("matrix", "include")
  require_gate(
    include_rows == [
      { "runner" => "ubuntu-24.04", "architecture" => "x86_64" },
      { "runner" => "ubuntu-24.04-arm", "architecture" => "aarch64" }
    ],
    "release_rehearsal_native_matrix_invalid"
  )
  native = active_step!(rehearsal, "verify native architecture")
  command!(native, 'test "$(uname -m)" = "${EXPECTED_ARCHITECTURE}"')
  active_step!(rehearsal, "verify Buildx")
  active_step!(rehearsal, "verify release metadata")
  scanner = active_step!(rehearsal, "verify installed release scanner version")
  command!(scanner, "--check-installed-tools --tool trivy")
  signature = active_step!(rehearsal, "sign and verify disposable local blob")
  command!(signature, "cosign sign-blob --yes --key cosign.key")
  command!(signature, "--bundle payload.sigstore.json payload.txt")
  command!(signature, "cosign verify-blob --key cosign.pub")
  before!(rehearsal, "install Buildx", "verify Buildx")
  before!(rehearsal, "derive release metadata", "verify release metadata")
  before!(rehearsal, "install Trivy", "verify installed release scanner version")
  before!(rehearsal, "install Cosign", "sign and verify disposable local blob")

  serialized_rehearsal = rehearsal_workflow.inspect
  [
    "packages\"=>\"write",
    "contents\"=>\"write",
    "id-token\"=>\"write",
    "docker push",
    "--push",
    "gh release",
    "cosign sign ",
    "actions/upload-artifact",
    "actions/attest"
  ].each do |forbidden|
    require_gate(
      !serialized_rehearsal.include?(forbidden),
      "release_rehearsal_publish_path:#{forbidden}"
    )
  end
end

def deep_copy(value)
  Marshal.load(Marshal.dump(value))
end

def expect_denied(workflows, fixture)
  yield workflows
  begin
    validate(workflows)
  rescue WorkflowError
    return
  end
  raise WorkflowError, "workflow_negative_fixture_accepted:#{fixture}"
end

def self_test(workflows)
  validate(workflows)

  comment_only = deep_copy(workflows)
  step!(job!(comment_only[:security], "gitleaks"), "verify installed scanner version")["run"] =
    "# python3 scripts/check-security-gates.py --check-installed-tools --tool gitleaks\n"
  expect_denied(comment_only, "comment_only") {}

  wrong_job = deep_copy(workflows)
  step = job!(wrong_job[:security], "gitleaks").fetch("steps").delete_at(3)
  job!(wrong_job[:security], "base-images").fetch("steps") << step
  expect_denied(wrong_job, "wrong_job") {}

  disabled = deep_copy(workflows)
  step!(job!(disabled[:go], "build-test"), "verify installed source scanner versions")["if"] =
    "${{ false }}"
  expect_denied(disabled, "disabled") {}

  nonblocking = deep_copy(workflows)
  step!(job!(nonblocking[:rust], "check-fast"), "verify installed dependency scanner versions")[
    "continue-on-error"
  ] = true
  expect_denied(nonblocking, "nonblocking") {}

  reordered = deep_copy(workflows)
  steps = job!(reordered[:security], "gitleaks").fetch("steps")
  verify_index = steps.index { |item| item["name"] == "verify installed scanner version" }
  scan_index = steps.index { |item| item["name"] == "scan history and prove the negative fixture" }
  steps[verify_index], steps[scan_index] = steps[scan_index], steps[verify_index]
  expect_denied(reordered, "reordered") {}

  wrong_production_mode = deep_copy(workflows)
  step!(
    job!(wrong_production_mode[:rust], "image"),
    "verify published engine digest and mode receipts"
  )["env"]["JANUS_PRODUCT_MODE"] = "enterprise"
  expect_denied(wrong_production_mode, "wrong_production_mode") {}

  missing_enterprise_receipt = deep_copy(workflows)
  step!(
    job!(missing_enterprise_receipt[:rust], "image"),
    "upload mode-specific admission receipts"
  )["run"] = 'gh release upload "$TAG" rust-engine-admission.json --clobber'
  expect_denied(missing_enterprise_receipt, "missing_enterprise_receipt") {}

  rehearsal_write = deep_copy(workflows)
  rehearsal_write[:rehearsal]["permissions"]["packages"] = "write"
  expect_denied(rehearsal_write, "release_rehearsal_write_permission") {}

  rehearsal_drift = deep_copy(workflows)
  action!(
    job!(rehearsal_drift[:rehearsal], "rehearse-release-tools"),
    "sigstore/cosign-installer"
  )["uses"] = "sigstore/cosign-installer@0000000000000000000000000000000000000000"
  expect_denied(rehearsal_drift, "release_rehearsal_action_drift") {}

  release_drift = deep_copy(workflows)
  action!(
    job!(release_drift[:go], "image"),
    "docker/metadata-action"
  )["uses"] = "docker/metadata-action@0000000000000000000000000000000000000000"
  expect_denied(release_drift, "release_action_drift") {}

  rehearsal_publish = deep_copy(workflows)
  step!(
    job!(rehearsal_publish[:rehearsal], "rehearse-release-tools"),
    "verify Buildx"
  )["run"] = "docker push ghcr.io/inspr-at/janus/rehearsal"
  expect_denied(rehearsal_publish, "release_rehearsal_publish_path") {}

  missing_arm = deep_copy(workflows)
  missing_arm[:rust].fetch("jobs").delete("image-arm64")
  expect_denied(missing_arm, "rust_native_arm_missing") {}

  qemu_release = deep_copy(workflows)
  job!(qemu_release[:rust], "image").fetch("steps") << {
    "uses" => "docker/setup-qemu-action@0000000000000000000000000000000000000000"
  }
  expect_denied(qemu_release, "rust_release_qemu_returned") {}

  native_rebuild = deep_copy(workflows)
  step!(job!(native_rebuild[:rust], "image-arm64"), "smoke native arm64 candidate")[
    "env"
  ]["JANUS_ENGINE_SMOKE_SKIP_BUILD"] = "false"
  expect_denied(native_rebuild, "rust_native_smoke_rebuilds") {}

  # JANUS-438: the go-only bypass must never be loosened, and the split
  # engine-assurance fan-in must never drop its completeness check.
  classify_trigger_widened = deep_copy(workflows)
  job!(classify_trigger_widened[:rust], "classify")["if"] = "true"
  expect_denied(classify_trigger_widened, "rust_classify_trigger_invalid") {}

  classify_command_widened = deep_copy(workflows)
  step!(job!(classify_command_widened[:rust], "classify"), "classify changed paths")["run"] =
    "python3 scripts/classify-pr-paths.py --files go-envelope/main.go"
  expect_denied(classify_command_widened, "rust_classify_command_invalid") {}

  classify_base_widened = deep_copy(workflows)
  step!(job!(classify_base_widened[:rust], "classify"), "classify changed paths").fetch("env")[
    "BASE_SHA"
  ] = "${{ github.event.pull_request.head.sha }}"
  expect_denied(classify_base_widened, "rust_classify_base_invalid") {}

  nix_gate_loosened = deep_copy(workflows)
  step!(job!(nix_gate_loosened[:rust], "check-nix"), "nix package")["if"] = "true"
  expect_denied(nix_gate_loosened, "nix_gate_loosened") {}

  nix_gate_removed = deep_copy(workflows)
  job!(nix_gate_removed[:rust], "check-nix").fetch("steps").delete_if do |step|
    step["name"] == "nix package not applicable (go-only change)"
  end
  expect_denied(nix_gate_removed, "nix_gate_removed") {}

  assurance_smoke_gate_loosened = deep_copy(workflows)
  step!(
    job!(assurance_smoke_gate_loosened[:rust], "check-assurance-smoke"),
    "engine release assurance gate (smoke)"
  )["if"] = "true"
  expect_denied(assurance_smoke_gate_loosened, "assurance_smoke_gate_loosened") {}

  assurance_fan_in_missing_inventory = deep_copy(workflows)
  job!(assurance_fan_in_missing_inventory[:rust], "check-assurance").fetch("steps").delete_if do |step|
    step["name"] == "verify engine assurance phase inventory"
  end
  expect_denied(assurance_fan_in_missing_inventory, "assurance_fan_in_missing_inventory") {}

  assurance_fan_in_missing_family = deep_copy(workflows)
  job!(assurance_fan_in_missing_family[:rust], "check-assurance")["needs"] = ["check-assurance-tests"]
  expect_denied(assurance_fan_in_missing_family, "assurance_fan_in_missing_family") {}
end

workflows = {
  go: load_workflow(File.join(ROOT, ".github/workflows/go-envelope.yml")),
  rust: load_workflow(File.join(ROOT, ".github/workflows/rust.yml")),
  security: load_workflow(File.join(ROOT, ".github/workflows/security.yml")),
  rehearsal: load_workflow(File.join(ROOT, ".github/workflows/release-tools-rehearsal.yml"))
}

begin
  ARGV.delete("--self-test") ? self_test(workflows) : validate(workflows)
rescue WorkflowError => e
  warn "workflow_security=blocked reason=#{e.message} value_returned=false"
  exit 1
end

puts "workflow_security=trusted value_returned=false"
