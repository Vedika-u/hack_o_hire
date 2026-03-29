# reasoning/output_parser.py
# Parses and validates LLM JSON output.
#
# LLMs fail in these specific ways:
# 1. JSON wrapped in markdown: ```json { ... } ```
# 2. Trailing commas: {"key": "value",}
# 3. Text before or after the JSON
# 4. Missing required fields
# 5. Actions outside the permitted whitelist
# 6. steps field is empty or missing
#
# This parser handles all six cases explicitly.
# It never crashes — always returns structured result or error.

import json
import re
from typing import Optional, List
from loguru import logger


class PlaybookOutputParser:

    REQUIRED_FIELDS = [
        "reasoning_trace",
        "threat_narrative",
        "attack_hypothesis",
        "steps"
    ]

    REQUIRED_STEP_FIELDS = [
        "step_number",
        "action",
        "target_entity",
        "reason"
    ]

    VALID_PRIORITIES = ["immediate", "within_1hr", "within_24hr"]

    def parse(self, raw_output: str) -> dict:
        """
        Parses raw LLM text into structured playbook data.

        Returns:
            success: bool
            data: dict or None
            error: str or None
        """
        if not raw_output or not raw_output.strip():
            return {
                "success": False,
                "data": None,
                "error": "LLM returned empty response"
            }

        # Extract JSON from raw text
        json_str = self._extract_json(raw_output)
        if not json_str:
            return {
                "success": False,
                "data": None,
                "error": (
                    "Could not find valid JSON in LLM output. "
                    f"Output starts with: {raw_output[:100]}"
                )
            }

        # Parse JSON
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            fixed = self._attempt_fix(json_str)
            if fixed is not None:
                data = fixed
            else:
                return {
                    "success": False,
                    "data": None,
                    "error": f"JSON parse error: {str(e)}"
                }

        # Validate required top-level fields
        missing = [
            f for f in self.REQUIRED_FIELDS
            if f not in data
        ]
        if missing:
            return {
                "success": False,
                "data": None,
                "error": f"Missing required fields: {missing}"
            }

        # Validate steps
        steps = data.get("steps", [])
        if not isinstance(steps, list) or len(steps) == 0:
            return {
                "success": False,
                "data": None,
                "error": "steps must be a non-empty list"
            }

        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                return {
                    "success": False,
                    "data": None,
                    "error": f"Step {i+1} is not a dict"
                }
            missing_step = [
                f for f in self.REQUIRED_STEP_FIELDS
                if f not in step
            ]
            if missing_step:
                return {
                    "success": False,
                    "data": None,
                    "error": (
                        f"Step {i+1} missing: {missing_step}"
                    )
                }

        # Enforce safety fields on all steps
        for step in data["steps"]:
            step["requires_approval"] = True
            step["approved"] = None
            step["executed"] = False
            step["approved_by"] = None
            step["approved_at"] = None
            step["executed_at"] = None
            # Normalize priority
            if step.get("priority") not in self.VALID_PRIORITIES:
                step["priority"] = "within_1hr"

        # Normalize confidence
        conf = data.get("confidence_in_hypothesis", 0.5)
        try:
            data["confidence_in_hypothesis"] = max(
                0.0, min(1.0, float(conf))
            )
        except (TypeError, ValueError):
            data["confidence_in_hypothesis"] = 0.5

        return {
            "success": True,
            "data": data,
            "error": None
        }

    def validate_constraints(
        self,
        parsed_data: dict,
        permitted_actions: List[str]
    ) -> dict:
        """
        Removes any steps with actions outside the permitted list.
        Records violations.
        A playbook with fewer valid steps is better than no playbook.
        """
        violations = []
        valid_steps = []

        for step in parsed_data.get("steps", []):
            action = step.get("action", "")
            if action in permitted_actions:
                valid_steps.append(step)
            else:
                msg = (
                    f"Step {step.get('step_number')}: "
                    f"'{action}' not in permitted list {permitted_actions}"
                )
                violations.append(msg)
                logger.warning(f"Constraint violation removed: {msg}")

        parsed_data["steps"] = valid_steps
        within_constraints = len(violations) == 0

        return {
            "data": parsed_data,
            "within_constraints": within_constraints,
            "validation_errors": violations
        }

    def _extract_json(self, text: str) -> Optional[str]:
        """
        Extracts JSON object from text.
        Handles markdown code blocks, preamble, postamble.
        """
        text = text.strip()

        # Already clean JSON
        if text.startswith("{"):
            # Find the matching closing brace
            depth = 0
            for i, char in enumerate(text):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return text[:i+1]
            return text

        # Inside markdown code block
        patterns = [
            r"```json\s*(\{.*?\})\s*```",
            r"```\s*(\{.*?\})\s*```",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1).strip()

        # JSON somewhere in the text
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return match.group(0).strip()

        return None

    def _attempt_fix(self, json_str: str) -> Optional[dict]:
        """Fixes common LLM JSON formatting errors."""
        try:
            # Fix trailing commas
            fixed = re.sub(r",\s*}", "}", json_str)
            fixed = re.sub(r",\s*]", "]", fixed)
            # Fix single quotes
            fixed = fixed.replace("'", '"')
            # Fix Python booleans
            fixed = fixed.replace("True", "true")
            fixed = fixed.replace("False", "false")
            fixed = fixed.replace("None", "null")
            return json.loads(fixed)
        except Exception:
            return None