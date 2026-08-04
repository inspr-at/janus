package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"unicode/utf8"
)

const (
	managedDynamicImportMaxBytes        = 1024
	managedDynamicEncodedValueMaxBytes  = managedDynamicImportMaxBytes * 3
	managedDynamicGeneratedEntropyBytes = 32
)

func (app *App) handleManagedDynamicValueAdmission(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	session := currentSession(r.Context())
	if !app.managedDynamicSetupEnabled() || app.managedDynamicCustody == nil || app.managedDynamicDelivery == nil || !app.cfg.RequireAuth {
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "dynamic setup unavailable")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "managed_setup_unavailable", "Managed environment setup is not ready.", nil)
		return
	}
	if !app.exactSameOriginBrowserMutation(r) ||
		!strictFormRequest(r, true) ||
		r.URL.RawQuery != "" ||
		r.ContentLength > managedFormPrefixMaxBytes+managedDynamicEncodedValueMaxBytes {
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "request integrity failed")
		app.renderSafeFailure(w, r, http.StatusForbidden, "request_integrity_failed", "Reload the setup page and try again.", nil)
		return
	}
	prefix, err := readManagedSecretFormPrefix(r.Body)
	if err != nil {
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "request form invalid")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "request_form_invalid", "Start again from Pharos with a new setup request.", nil)
		return
	}
	defer zeroizeBytes(prefix)
	humanSessionRef := managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject)
	proof, proofOK := app.readManagedDynamicStepUpProof(r)
	if !proofOK || proof.Target.HumanSessionRef != humanSessionRef ||
		!validateManagedSecretFormPrefix(prefix, app.csrfToken(session), proof.Target.IntentRef, proof.Target.Source) {
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "proof or form binding invalid")
		app.renderSafeFailure(w, r, http.StatusForbidden, "passwordless_step_up_required", "Confirm this exact setup request with your passkey again.", nil)
		return
	}
	reservation, err := app.managedDynamicSetup.BeginValueAdmission(r.Context(), proof.Target, proof.OperationRef)
	if err != nil {
		if managedDynamicValueAlreadyAdmitted(err) {
			recovered, recoverErr := app.managedDynamicSetup.RecoverReservation(r.Context(), proof.Target.IntentRef, proof.Target.HumanSessionRef, proof.OperationRef)
			if recoverErr == nil && recovered.ValueAdmissionComplete {
				w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
				app.audit(r, "managed_environment.value.admit", "allowed", session.Subject, "duplicate resolved to existing value-free custody state")
				http.Redirect(w, r, "/managed-environment/setup?intent="+url.QueryEscape(proof.Target.IntentRef), http.StatusSeeOther)
				return
			}
			if recoverErr == nil && recovered.ValueAdmissionStarted {
				custody, custodyErr := app.managedDynamicCustody.Recover(r.Context(), proof.Target, proof.OperationRef)
				if custodyErr == nil {
					delivery, deliveryErr := app.managedDynamicDelivery.Prepare(r.Context(), proof.Target, proof.OperationRef, custody)
					if deliveryErr == nil {
						completed, completeErr := app.managedDynamicSetup.CompleteValueAdmission(r.Context(), proof.Target, proof.OperationRef, custody, delivery)
						if completeErr == nil && completed.ValueAdmissionComplete && completed.BindingRef == custody.BindingRef && completed.SecretRef == custody.SecretRef && completed.GenerationRef == custody.GenerationRef && completed.PackageRef == delivery.PackageRef && completed.EnvelopeRef == delivery.EnvelopeRef {
							w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
							app.audit(r, "managed_environment.value.admit", "allowed", session.Subject, "lost custody response recovered without reading submitted value")
							http.Redirect(w, r, "/managed-environment/setup?intent="+url.QueryEscape(proof.Target.IntentRef), http.StatusSeeOther)
							return
						}
					}
				}
			}
		}
		app.clearManagedDynamicStepUpProofCookies(w)
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "value admission unavailable")
		app.renderSafeFailure(w, r, managedIntentHTTPStatus(err), "value_admission_unavailable", "This value was not accepted. Start again from Pharos with a new setup request.", nil)
		return
	}
	if reservation.OperationRef != proof.OperationRef ||
		managedDynamicTargetFromInspection(reservation.Inspection) != proof.Target ||
		!reservation.ValueAdmissionStarted || reservation.ValueAdmissionComplete {
		app.clearManagedDynamicStepUpProofCookies(w)
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "value admission state invalid")
		app.renderSafeFailure(w, r, http.StatusConflict, "value_admission_unavailable", "This value was not accepted. Start again from Pharos with a new setup request.", nil)
		return
	}

	remaining := r.ContentLength - int64(len(prefix))
	value, err := processManagedDynamicValue(r.Body, remaining, proof.Target.Source, rand.Reader)
	if err != nil {
		app.clearManagedDynamicStepUpProofCookies(w)
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "value shape rejected after single-use admission began")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "value_not_accepted", "The value did not match the approved single-line contract. Start again from Pharos.", nil)
		return
	}
	defer zeroizeBytes(value)
	custody, err := app.managedDynamicCustody.Custody(r.Context(), proof.Target, proof.OperationRef, value)
	if err != nil {
		custody, err = app.managedDynamicCustody.Recover(r.Context(), proof.Target, proof.OperationRef)
	}
	if err != nil || validateManagedDynamicCustodyResult(custody, proof.OperationRef) != nil {
		app.clearManagedDynamicStepUpProofCookies(w)
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "encrypted custody unavailable after single-use admission began")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "value_custody_unavailable", "Janus could not confirm encrypted custody. Start again from Pharos; the submitted value cannot be reused.", nil)
		return
	}
	delivery, err := app.managedDynamicDelivery.Prepare(r.Context(), proof.Target, proof.OperationRef, custody)
	if err != nil || validateManagedDynamicDeliveryResult(delivery, proof.OperationRef) != nil {
		app.clearManagedDynamicStepUpProofCookies(w)
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "host-bound package unavailable after encrypted custody")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "value_delivery_unavailable", "Janus encrypted the value but could not prepare its host-bound package. Start again from Pharos.", nil)
		return
	}
	completed, err := app.managedDynamicSetup.CompleteValueAdmission(r.Context(), proof.Target, proof.OperationRef, custody, delivery)
	if err != nil || completed.OperationRef != proof.OperationRef ||
		managedDynamicTargetFromInspection(completed.Inspection) != proof.Target ||
		!completed.ValueAdmissionStarted || !completed.ValueAdmissionComplete ||
		completed.BindingRef != custody.BindingRef || completed.SecretRef != custody.SecretRef ||
		completed.GenerationRef != custody.GenerationRef || completed.PackageRef != delivery.PackageRef ||
		completed.EnvelopeRef != delivery.EnvelopeRef {
		app.clearManagedDynamicStepUpProofCookies(w)
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		app.audit(r, "managed_environment.value.admit", "denied", session.Subject, "value-free custody receipt unavailable")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "value_admission_incomplete", "Janus prepared the encrypted host package but could not confirm its value-free receipt. Start again from Pharos.", nil)
		return
	}
	w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	app.audit(r, "managed_environment.value.admit", "allowed", session.Subject, "one bounded value stored in custody and prepared as a host-bound package")
	http.Redirect(w, r, "/managed-environment/setup?intent="+url.QueryEscape(proof.Target.IntentRef), http.StatusSeeOther)
}

func processManagedDynamicValue(reader io.Reader, remaining int64, source string, random io.Reader) ([]byte, error) {
	if reader == nil || remaining < 0 || remaining > managedDynamicEncodedValueMaxBytes {
		return nil, errors.New("managed dynamic value body invalid")
	}
	rawValue := make([]byte, int(remaining))
	defer zeroizeBytes(rawValue)
	if _, err := io.ReadFull(reader, rawValue); err != nil || !requestBodyAtEOF(reader) {
		return nil, errors.New("managed dynamic value body incomplete")
	}
	value, err := decodeManagedFormValueInPlace(rawValue)
	if err != nil {
		return nil, err
	}
	switch source {
	case "import":
		if err := validateManagedDynamicValue(value); err != nil {
			return nil, err
		}
		return append([]byte(nil), value...), nil
	case "generated":
		if len(value) != 0 {
			return nil, errors.New("managed dynamic generated value must be internal")
		}
		generated, err := generateManagedDynamicValue(random)
		if err != nil {
			return nil, err
		}
		if err := validateManagedDynamicValue(generated); err != nil {
			zeroizeBytes(generated)
			return nil, err
		}
		return generated, nil
	default:
		return nil, errors.New("managed dynamic value source invalid")
	}
}

func validateManagedDynamicValue(value []byte) error {
	if len(value) == 0 || len(value) > managedDynamicImportMaxBytes ||
		!utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 ||
		bytes.IndexByte(value, '\r') >= 0 || bytes.IndexByte(value, '\n') >= 0 {
		return errors.New("managed dynamic value contract invalid")
	}
	return nil
}

func generateManagedDynamicValue(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, errors.New("managed dynamic generator unavailable")
	}
	entropy := make([]byte, managedDynamicGeneratedEntropyBytes)
	defer zeroizeBytes(entropy)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return nil, errors.New("managed dynamic generator unavailable")
	}
	value := make([]byte, base64.RawURLEncoding.EncodedLen(len(entropy)))
	base64.RawURLEncoding.Encode(value, entropy)
	return value, nil
}

func managedDynamicValueAlreadyAdmitted(err error) bool {
	var managed managedIntentError
	return errors.As(err, &managed) && managed == "managed_intent_value_replayed"
}
