from config.schemas import PlaybookStep, SOARConstraints
from soar.executor import execute_step
from datetime import datetime, timezone

step = PlaybookStep(
    step_number=1,
    action="alert_analyst",
    target_entity="user_lateral_001",
    reason="Test execution",
    priority="immediate",
    requires_approval=True,
    approved=True,
    approved_by="analyst1",
    approved_at=datetime.now(timezone.utc),
    executed=False,
    executed_at=None
)

constraints = SOARConstraints()

result = execute_step(
    step=step,
    constraints=constraints,
    executor_username="manager1",
    executor_role="soc_manager",
    pipeline_id="test-pipeline-123",
    incident_id="test-incident-123"
)

print(f"Success: {result.success}")
print(f"Message: {result.message}")
print(f"Details: {result.details}")