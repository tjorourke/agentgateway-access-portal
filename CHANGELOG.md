# Changelog

## 0.1.2

Register the Kyverno chart repository in clean CI environments and installation
instructions so dependency builds work with Helm 3 as well as Helm 4.

## 0.1.1

Explicitly limit Python package discovery to the application. Fresh repository
installs now exclude Helm chart directories from Python package detection.

## 0.1.0

Initial standalone release: organisation-neutral employee and administrator portal,
OIDC group-based roles, first-install and day-two settings, gateway discovery,
encrypted token values, lifecycle policies, and a Helm chart with optional pinned
Kyverno installation.
