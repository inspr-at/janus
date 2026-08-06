# JANUS-405 login trust layout

## Problem

The previous narrow, tall sign-in card floated over the lower centre of the Janus sculpture. That obscured the hero artwork and made the trust boundary look like an accidental modal.

## Design decision

Keep the complete Janus sculpture visible in a dedicated hero stage, then place the sign-in experience in normal document flow immediately below it. On desktop, use a shorter two-column panel: purpose and the single action on the left, trust statements on the right. On narrow screens, stack those columns and allow normal vertical scrolling.

The generated image is a layout reference only. The shipped interface is implemented with HTML and responsive CSS; no generated pixels are used in the product.

## Files

- `current-login.png`: authoritative ticket screenshot showing the obstruction.
- `proposed-login.png`: ImageGen layout proposal used to guide the implementation.

## ImageGen record

Mode: precise object edit of the authoritative screenshot.

Prompt:

> Use case: precise-object-edit. Asset type: desktop web login-page redesign reference. Image 1 is the authoritative current Janus login screenshot and the edit target. Change only the centered sign-in card layout and position so it no longer covers any part of the central two-faced Janus sculpture. Place the complete sign-in experience in a dedicated centered band immediately below the fully visible sculpture. Redesign the card as a wider, substantially shorter two-column panel. Left column: eyebrow, heading, explanatory copy, and primary button. Right column: the three existing trust statements. Keep a subtle hairline border, restrained glass-white surface, modest radius, and soft shadow. The panel must feel calm and intentional, not like a floating modal. Preserve unchanged: the entire header and its Janus logo/build label; the top-right identity notice; the full hero sculpture, lighting, colour treatment, and composition; both side rails and their wording; the light restrained Janus visual language. Text verbatim: "self_hosted · secure sign-in"; "Open Janus"; "Sign in with Zitadel to see the secret catalog, role-gated actions, and value-free evidence for this browser."; "Continue with Zitadel"; "Janus never asks for or shows a secret value, in either direction."; "Identity stays out of access and evidence pages."; "Verified boundary: value_returned=false". Preserve the 2000 × 1427 desktop screenshot framing; full Janus sculpture unobstructed; no new copy; no removed controls; one clear sign-in action; no extra logos; no watermark; no dark mode; no decorative concept-art changes.
