package domain

import (
	"testing"
	"time"

	"github.com/MagalixTechnologies/uuid-go"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestPolicyToEvent(t *testing.T) {
	policy := Policy{
		ID:       uuid.NewV4().String(),
		Name:     "my-policy",
		Category: "my-category",
		Severity: "low",
		Reference: v1.ObjectReference{
			UID:             "my-policy",
			APIVersion:      "pac.weave.works/v1",
			Kind:            "Policy",
			Name:            "my-policy",
			ResourceVersion: "1",
		},
	}

	entity := Entity{
		ID:              uuid.NewV4().String(),
		APIVersion:      "v1",
		Kind:            "Deployment",
		Name:            "my-deployment",
		Namespace:       "default",
		Manifest:        map[string]interface{}{},
		ResourceVersion: "1",
		Labels:          map[string]string{},
	}

	results := []PolicyValidation{
		{
			Policy:    policy,
			Entity:    entity,
			Status:    PolicyValidationStatusViolating,
			Message:   "message",
			Type:      "Admission",
			Trigger:   "Admission",
			CreatedAt: time.Now(),
		},
		{
			Policy:    policy,
			Entity:    entity,
			Status:    PolicyValidationStatusCompliant,
			Message:   "message",
			Type:      "Audit",
			Trigger:   "PolicyChange",
			CreatedAt: time.Now(),
		},
	}

	for _, result := range results {
		event := NewK8sEventFromPolicyVlidation(result)

		if result.Status == PolicyValidationStatusViolating {
			assert.Equal(t, event.Type, v1.EventTypeWarning)
			assert.Equal(t, event.Reason, EventReasonPolicyViolation)
			assert.Equal(t, event.Action, EventActionRejected)

		} else if result.Status == PolicyValidationStatusCompliant {
			assert.Equal(t, event.Type, v1.EventTypeNormal)
			assert.Equal(t, event.Reason, EventReasonPolicyCompliance)
			assert.Equal(t, event.Action, EventActionAllowed)
		}

		// verify involved object holds entity info
		assert.Equal(t, event.InvolvedObject.APIVersion, entity.APIVersion)
		assert.Equal(t, event.InvolvedObject.Kind, entity.Kind)
		assert.Equal(t, event.InvolvedObject.Name, entity.Name)
		assert.Equal(t, event.InvolvedObject.Namespace, entity.Namespace)

		// verify involved object holds entity info
		policyRef := policy.Reference.(v1.ObjectReference)
		assert.Equal(t, event.Related.APIVersion, policyRef.APIVersion)
		assert.Equal(t, event.Related.Kind, policyRef.Kind)
		assert.Equal(t, event.Related.Name, policyRef.Name)

		// verify event message
		assert.Equal(t, event.Message, result.Message)

		// verify metadata
		assert.Equal(t, event.Annotations, map[string]string{
			"account_id": result.AccountID,
			"cluster_id": result.ClusterID,
			"id":         result.ID,
			"policy":     result.Policy.ID,
			"severity":   result.Policy.Severity,
			"category":   result.Policy.Category,
			"type":       result.Type,
			"trigger":    result.Trigger,
		})
	}
}

func TestEventToPolicy(t *testing.T) {
	event := v1.Event{
		InvolvedObject: v1.ObjectReference{
			APIVersion:      "v1",
			Kind:            "Deployment",
			UID:             types.UID(uuid.NewV4().String()),
			Name:            "my-deployment",
			Namespace:       "default",
			ResourceVersion: "1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"account_id": uuid.NewV4().String(),
				"cluster_id": uuid.NewV4().String(),
				"id":         uuid.NewV4().String(),
				"type":       "Admission",
				"trigger":    "Admission",
				"policy":     uuid.NewV4().String(),
				"category":   "category",
				"severity":   "high",
			},
		},
		Message: "Policy event",
		Reason:  "PolicyViolation",
		Related: &v1.ObjectReference{
			UID:             "my-policy",
			APIVersion:      "pac.weave.works/v1",
			Kind:            "Policy",
			Name:            "my-policy",
			ResourceVersion: "1",
		},
	}

	policyValidation := NewPolicyValidationFRomK8sEvent(&event)

	assert.Equal(t, policyValidation.Status, PolicyValidationStatusViolating)
	assert.Equal(t, event.InvolvedObject.APIVersion, policyValidation.Entity.APIVersion)
	assert.Equal(t, event.InvolvedObject.Kind, policyValidation.Entity.Kind)
	assert.Equal(t, event.InvolvedObject.Name, policyValidation.Entity.Name)
	assert.Equal(t, event.InvolvedObject.Namespace, policyValidation.Entity.Namespace)

	policyRef := policyValidation.Policy.Reference.(*v1.ObjectReference)
	assert.Equal(t, event.Related.APIVersion, policyRef.APIVersion)
	assert.Equal(t, event.Related.Kind, policyRef.Kind)
	assert.Equal(t, event.Related.Name, policyRef.Name)

	assert.Equal(t, event.Message, policyValidation.Message)

	// verify metadata
	assert.Equal(t, event.Annotations, map[string]string{
		"account_id": policyValidation.AccountID,
		"cluster_id": policyValidation.ClusterID,
		"id":         policyValidation.ID,
		"policy":     policyValidation.Policy.ID,
		"severity":   policyValidation.Policy.Severity,
		"category":   policyValidation.Policy.Category,
		"type":       policyValidation.Type,
		"trigger":    policyValidation.Trigger,
	})
}
