package domain

import (
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	PolicyValidationStatusViolating = "Violation"
	PolicyValidationStatusCompliant = "Compliance"
	EventActionAllowed              = "Allowed"
	EventActionRejected             = "Rejected"
	EventReasonPolicyViolation      = "PolicyViolation"
	EventReasonPolicyCompliance     = "PolicyCompliance"
	PolicyValidationEventLabelKey   = "policy-validation.weave.works"
)

// PolicyValidation defines the result of a policy validation result against an entity
type PolicyValidation struct {
	ID        string                 `json:"id"`
	AccountID string                 `json:"account_id"`
	ClusterID string                 `json:"cluster_id"`
	Policy    Policy                 `json:"policy"`
	Entity    Entity                 `json:"entity"`
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"-"`
	Type      string                 `json:"source"`
	Trigger   string                 `json:"trigger"`
	CreatedAt time.Time              `json:"created_at"`
}

// PolicyValidationSummary contains violation and compliance result of a validate operation
type PolicyValidationSummary struct {
	Violations  []PolicyValidation
	Compliances []PolicyValidation
}

// GetViolationMessages get all violation messages from review results
func (v *PolicyValidationSummary) GetViolationMessages() []string {
	var messages []string
	for _, violation := range v.Violations {
		messages = append(messages, violation.Message)
	}
	return messages
}

// NewK8sEventFromPolicyVlidation gets kubernetes event object from policy violation result object
func NewK8sEventFromPolicyVlidation(result PolicyValidation) v1.Event {
	var reason, action, etype string

	if result.Status == PolicyValidationStatusViolating {
		etype = v1.EventTypeWarning
		reason = EventReasonPolicyViolation
		action = EventActionRejected
	} else {
		etype = v1.EventTypeNormal
		reason = EventReasonPolicyCompliance
		action = EventActionAllowed
	}

	annotations := map[string]string{
		"account_id": result.AccountID,
		"cluster_id": result.ClusterID,
		"id":         result.ID,
		"policy":     result.Policy.ID,
		"severity":   result.Policy.Severity,
		"category":   result.Policy.Category,
		"type":       result.Type,
		"trigger":    result.Trigger,
	}

	namespace := result.Entity.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceDefault
	}

	involvedObject := result.Entity.ObjectRef()
	relatedObject := result.Policy.ObjectRef()

	timestamp := metav1.NewTime(time.Now())

	event := v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%v.%x", result.Entity.Name, timestamp.UnixNano()),
			Namespace:   namespace,
			Annotations: annotations,
			Labels:      map[string]string{PolicyValidationEventLabelKey: result.Type},
		},
		InvolvedObject: *involvedObject,
		Related:        relatedObject,
		Type:           etype,
		Reason:         reason,
		Action:         action,
		Message:        result.Message,
		FirstTimestamp: timestamp,
		LastTimestamp:  timestamp,
	}

	return event
}

// NewPolicyValidationFRomK8sEvent gets policy violation result object from kubernetes event object
func NewPolicyValidationFRomK8sEvent(event *v1.Event) PolicyValidation {
	annotations := event.ObjectMeta.Annotations
	var status string
	if event.Reason == EventReasonPolicyViolation {
		status = PolicyValidationStatusViolating
	} else {
		status = PolicyValidationStatusCompliant
	}
	return PolicyValidation{
		AccountID: annotations["account_id"],
		ClusterID: annotations["cluster_id"],
		ID:        annotations["id"],
		Type:      annotations["type"],
		Trigger:   annotations["trigger"],
		CreatedAt: event.FirstTimestamp.Time,
		Message:   event.Message,
		Status:    status,
		Policy: Policy{
			ID:        annotations["policy"],
			Category:  annotations["category"],
			Severity:  annotations["severity"],
			Reference: event.Related,
		},
		Entity: Entity{
			APIVersion:      event.InvolvedObject.APIVersion,
			Kind:            event.InvolvedObject.Kind,
			ID:              string(event.InvolvedObject.UID),
			Name:            event.InvolvedObject.Name,
			Namespace:       event.InvolvedObject.Namespace,
			ResourceVersion: event.InvolvedObject.ResourceVersion,
		},
	}
}
