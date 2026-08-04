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

  rust_check = job!(workflows.fetch(:rust), "check")
  rust_dependency_verify = active_step!(rust_check, "verify installed dependency scanner versions")
  command!(rust_dependency_verify, "--tool cargo-audit --tool gitleaks")
  active_step!(rust_check, "release security policy and negative fixtures")
  active_step!(rust_check, "engine release assurance gate")
  rust_image_verify = active_step!(rust_check, "verify installed image scanner version")
  command!(rust_image_verify, "--tool trivy")
  active_step!(rust_check, "scan candidate image and emit value-free summary")
  before!(rust_check, "verify installed dependency scanner versions", "release security policy and negative fixtures")
  before!(rust_check, "verify installed dependency scanner versions", "engine release assurance gate")
  before!(rust_check, "verify installed image scanner version", "scan candidate image and emit value-free summary")

  rust_image = job!(workflows.fetch(:rust), "image")
  active_step!(rust_image, "verify protected-main release ancestry")
  active_step!(rust_image, "verify installed release scanner version")
  rust_published_scan = active_step!(rust_image, "scan exact published candidate digest")
  command!(rust_published_scan, '--subject "${IMAGE}@${{ steps.build.outputs.digest }}"')
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

  [
    "docker/setup-buildx-action",
    "docker/login-action",
    "docker/metadata-action",
    "aquasecurity/setup-trivy",
    "sigstore/cosign-installer"
  ].each do |repository|
    require_gate(
      action!(go_image, repository)["uses"] == action!(rust_image, repository)["uses"],
      "release_action_drift:#{repository}"
    )
  end

  {
    "actions/checkout" => action!(rust_check, "actions/checkout")["uses"],
    "docker/setup-qemu-action" => action!(rust_image, "docker/setup-qemu-action")["uses"],
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

  arm = active_step!(rehearsal, "verify ARM emulation")
  command!(arm, 'docker run --rm --platform linux/arm64 "${runtime_image}"')
  active_step!(rehearsal, "verify Buildx")
  active_step!(rehearsal, "verify release metadata")
  scanner = active_step!(rehearsal, "verify installed release scanner version")
  command!(scanner, "--check-installed-tools --tool trivy")
  signature = active_step!(rehearsal, "sign and verify disposable local blob")
  command!(signature, "cosign sign-blob --yes --key cosign.key")
  command!(signature, "--bundle payload.sigstore.json payload.txt")
  command!(signature, "cosign verify-blob --key cosign.pub")
  before!(rehearsal, "install QEMU emulation", "verify ARM emulation")
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
  step!(job!(nonblocking[:rust], "check"), "verify installed dependency scanner versions")[
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
