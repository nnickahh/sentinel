"""
Sentinel NVIDIA Nemotron Privacy Intelligence Agent
Interacts with NVIDIA Nemotron via Nebius Token Factory (OpenAI-compatible endpoint).
Produces structured JSON telemetry classifications, risk assessments, and action plans.
Includes defensive error recovery and fallback handling.
"""
import json
import logging
import re
from typing import List, Dict, Any, Optional

from openai import AsyncOpenAI

from backend.config import settings
from backend.models import (
    ConnectionEvent,
    NemotronAnalysis,
    ProtectMeBatchResponse,
    ProtectMeBatchItem,
    RiskLevel,
    ActionDecision,
    UserDecisionRecord,
    AskQuestionResponse
)
from privacy_engine.sanitizer import PrivacySanitizer
from agent.prompts import (
    NEMOTRON_SYSTEM_PROMPT,
    INVESTIGATE_PROMPT_TEMPLATE,
    PROTECT_ME_PROMPT_TEMPLATE,
    PRIVACY_REPORT_PROMPT_TEMPLATE,
    ASK_QUESTION_PROMPT_TEMPLATE
)
from agent.fallback_engine import FallbackPrivacyEngine

logger = logging.getLogger("sentinel.agent")

class NemotronPrivacyAgent:
    def __init__(self):
        self._client: Optional[AsyncOpenAI] = None
        self._init_client()

    def _init_client(self):
        """Initialize or reload AsyncOpenAI client with current Nebius settings."""
        if settings.is_nebius_configured():
            try:
                self._client = AsyncOpenAI(
                    api_key=settings.nebius_api_key.strip(),
                    base_url=settings.nebius_base_url.strip(),
                    timeout=float(settings.nebius_timeout)
                )
                logger.info(f"Connected to Nebius Token Factory at {settings.nebius_base_url}")
            except Exception as e:
                logger.warning(f"Could not initialize Nebius client: {e}")
                self._client = None
        else:
            self._client = None

    def is_connected(self) -> bool:
        """Check if Nebius Token Factory connection is configured."""
        return self._client is not None and settings.is_nebius_configured()

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        """Defensively extract JSON from model output, handling fences or preamble."""
        clean_text = text.strip()
        
        # Strip markdown fences if present
        if clean_text.startswith("```"):
            clean_text = re.sub(r"^```(?:json)?\s*", "", clean_text)
            clean_text = re.sub(r"\s*```$", "", clean_text)
            
        # Try direct parse
        try:
            return json.loads(clean_text)
        except json.JSONDecodeError:
            pass
            
        # Find first { and last }
        match = re.search(r"(\{.*\})", clean_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
                
        raise ValueError(f"Could not parse valid JSON from model response: {text[:200]}")

    async def investigate_connection(
        self,
        event: ConnectionEvent,
        past_decision: Optional[UserDecisionRecord] = None
    ) -> NemotronAnalysis:
        """
        Investigate a single network connection using NVIDIA Nemotron via Nebius.
        Extracts structured risk assessment and consequences.
        """
        # Step 1: Enforce privacy guardrails - sanitize event
        sanitized = PrivacySanitizer.sanitize_for_nemotron(event)
        sanitized_json = sanitized.model_dump_json(indent=2)
        
        past_context = ""
        if past_decision:
            past_context = (
                f"PAST USER DECISION:\n"
                f"The user previously chose to '{past_decision.decision.value}' connections to this domain "
                f"(Decision logged at {past_decision.timestamp}). Keep this policy preference in mind."
            )

        prompt = INVESTIGATE_PROMPT_TEMPLATE.format(
            sanitized_json=sanitized_json,
            past_context=past_context
        )

        # If Nebius is not configured, gracefully use local fallback engine
        if not self.is_connected():
            logger.info("Nebius API key not set or offline. Using Sentinel Local Fallback Engine.")
            return FallbackPrivacyEngine.investigate(
                domain=event.domain,
                application=event.application,
                category=event.category.value,
                frequency=event.connection_count,
                past_decision=past_decision
            )

        try:
            response = await self._client.chat.completions.create(
                model=settings.nebius_model,
                messages=[
                    {"role": "system", "content": NEMOTRON_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0,
                max_tokens=1200
            )
            raw_content = response.choices[0].message.content or ""
            data = self._extract_json(raw_content)

            # Defensive field mapping
            risk_val = data.get("risk", "medium").lower()
            risk_enum = RiskLevel(risk_val) if risk_val in RiskLevel._value2member_map_ else RiskLevel.MEDIUM

            rec_val = data.get("recommendation", "block").lower()
            rec_enum = ActionDecision(rec_val) if rec_val in ActionDecision._value2member_map_ else ActionDecision.BLOCK

            consequences = data.get("possible_consequences", [])
            if not isinstance(consequences, list):
                consequences = [str(consequences)]

            return NemotronAnalysis(
                risk=risk_enum,
                category=data.get("category", event.category.value),
                recommendation=rec_enum,
                confidence=float(data.get("confidence", 0.90)),
                explanation=data.get("explanation", "Investigated by NVIDIA Nemotron"),
                possible_consequences=consequences,
                vendor_profile=data.get("vendor_profile", event.vendor),
                source_model=f"NVIDIA Nemotron ({settings.nebius_model})"
            )

        except Exception as e:
            logger.error(f"Error calling Nebius Token Factory Nemotron: {e}. Falling back to local engine.")
            analysis = FallbackPrivacyEngine.investigate(
                domain=event.domain,
                application=event.application,
                category=event.category.value,
                frequency=event.connection_count,
                past_decision=past_decision
            )
            analysis.source_model = f"Local Fallback (Nebius error: {str(e)[:40]}...)"
            return analysis

    async def evaluate_protect_me_batch(
        self,
        events: List[ConnectionEvent],
        past_decisions: Dict[str, UserDecisionRecord]
    ) -> ProtectMeBatchResponse:
        """
        Evaluate batch of connections for the 'Protect Me' agent flow.
        """
        if not events:
            return ProtectMeBatchResponse(
                analyzed_count=0,
                recommended_block_count=0,
                recommended_keep_count=0,
                narrative="No active connections to evaluate.",
                items=[]
            )

        # Sanitize all events
        sanitized_batch = [PrivacySanitizer.sanitize_for_nemotron(ev).model_dump() for ev in events]
        connections_json = json.dumps(sanitized_batch, indent=2)

        past_context = ""
        if past_decisions:
            past_list = [
                f"- {dom}: previously {rec.decision.value}"
                for dom, rec in list(past_decisions.items())[:5]
            ]
            past_context = "PREVIOUS USER DECISIONS:\n" + "\n".join(past_list)

        prompt = PROTECT_ME_PROMPT_TEMPLATE.format(
            connections_json=connections_json,
            past_context=past_context
        )

        if not self.is_connected():
            return FallbackPrivacyEngine.evaluate_protect_me(events, past_decisions)

        try:
            response = await self._client.chat.completions.create(
                model=settings.nebius_model,
                messages=[
                    {"role": "system", "content": NEMOTRON_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1200
            )
            raw_content = response.choices[0].message.content or ""
            data = self._extract_json(raw_content)

            items_raw = data.get("items", [])
            items: List[ProtectMeBatchItem] = []
            block_count = 0
            keep_count = 0

            for it in items_raw:
                action_str = it.get("recommended_action", "block").lower()
                action_enum = ActionDecision(action_str) if action_str in ActionDecision._value2member_map_ else ActionDecision.BLOCK
                risk_str = it.get("risk", "medium").lower()
                risk_enum = RiskLevel(risk_str) if risk_str in RiskLevel._value2member_map_ else RiskLevel.MEDIUM

                should_block = action_enum in [ActionDecision.BLOCK]
                if should_block:
                    block_count += 1
                else:
                    keep_count += 1

                items.append(
                    ProtectMeBatchItem(
                        domain=it.get("domain", "unknown"),
                        application=it.get("application", "unknown"),
                        category=it.get("category", "analytics"),
                        risk=risk_enum,
                        recommended_action=action_enum,
                        confidence=float(it.get("confidence", 0.90)),
                        explanation=it.get("explanation", "Evaluated by Nemotron"),
                        consequences=it.get("consequences", ["Tracking prevented"]),
                        selected=should_block
                    )
                )

            narrative = data.get(
                "narrative",
                f"I evaluated {len(items)} connections and recommend blocking {block_count} trackers."
            )

            return ProtectMeBatchResponse(
                analyzed_count=len(items),
                recommended_block_count=block_count,
                recommended_keep_count=keep_count,
                narrative=narrative,
                items=items
            )

        except Exception as e:
            logger.error(f"Nebius Protect Me batch failed: {e}. Falling back to local engine.")
            return FallbackPrivacyEngine.evaluate_protect_me(events, past_decisions)

    async def generate_privacy_report(
        self,
        privacy_score: int,
        total_connections: int,
        trackers_detected: int,
        blocked_count: int,
        high_risk_count: int,
        top_apps: List[Dict[str, Any]],
        recent_events: List[ConnectionEvent]
    ) -> str:
        """Generate high-level privacy audit narrative using Nemotron."""
        if not self.is_connected():
            return FallbackPrivacyEngine.generate_report_narrative(
                privacy_score, total_connections, trackers_detected,
                blocked_count, high_risk_count, top_apps
            )

        events_summary = [
            {"app": ev.application, "domain": ev.domain, "category": ev.category.value, "risk": ev.risk_level.value, "status": ev.status.value}
            for ev in recent_events[:8]
        ]

        prompt = PRIVACY_REPORT_PROMPT_TEMPLATE.format(
            privacy_score=privacy_score,
            total_connections=total_connections,
            trackers_detected=trackers_detected,
            blocked_count=blocked_count,
            high_risk_count=high_risk_count,
            top_apps_json=json.dumps(top_apps, indent=2),
            events_summary_json=json.dumps(events_summary, indent=2)
        )

        try:
            response = await self._client.chat.completions.create(
                model=settings.nebius_model,
                messages=[
                    {"role": "system", "content": NEMOTRON_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=800
            )
            return response.choices[0].message.content or FallbackPrivacyEngine.generate_report_narrative(
                privacy_score, total_connections, trackers_detected, blocked_count, high_risk_count, top_apps
            )
        except Exception as e:
            logger.warning(f"Nemotron report generation error: {e}. Using fallback narrative.")
            return FallbackPrivacyEngine.generate_report_narrative(
                privacy_score, total_connections, trackers_detected, blocked_count, high_risk_count, top_apps
            )

    async def ask_question(
        self,
        question: str,
        events: List[ConnectionEvent],
        rules: List[UserDecisionRecord],
        privacy_score: int,
        privacy_mode: str = "normal"
    ) -> AskQuestionResponse:
        """
        Answer natural-language user privacy questions using NVIDIA Nemotron via Nebius Token Factory.
        """
        if not self.is_connected():
            return FallbackPrivacyEngine.answer_question(question, events, privacy_score, privacy_mode)

        events_summary = [
            {
                "app": ev.application,
                "domain": ev.domain,
                "ip": ev.ip,
                "category": ev.category.value,
                "risk": ev.risk_level.value,
                "status": ev.status.value,
                "packets": ev.connection_count,
                "details": ev.details
            }
            for ev in events[:12]
        ]
        rules_summary = [
            {"app": r.application, "domain": r.domain, "decision": r.decision.value}
            for r in rules[:10]
        ]

        prompt = ASK_QUESTION_PROMPT_TEMPLATE.format(
            question=question,
            privacy_mode=privacy_mode,
            privacy_score=privacy_score,
            events_json=json.dumps(events_summary, indent=2),
            rules_json=json.dumps(rules_summary, indent=2)
        )

        try:
            response = await self._client.chat.completions.create(
                model=settings.nebius_model,
                messages=[
                    {"role": "system", "content": NEMOTRON_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=800
            )
            raw_content = response.choices[0].message.content or ""
            data = self._extract_json(raw_content)

            return AskQuestionResponse(
                question=question,
                answer=data.get("answer", "Analyzed by NVIDIA Nemotron."),
                related_apps=data.get("related_apps", []),
                related_domains=data.get("related_domains", []),
                risk_summary=data.get("risk_summary", "medium"),
                recommended_actions=data.get("recommended_actions", []),
                source_model=f"NVIDIA Nemotron ({settings.nebius_model})"
            )
        except Exception as e:
            logger.warning(f"Nemotron ask_question error: {e}. Falling back to local engine.")
            return FallbackPrivacyEngine.answer_question(question, events, privacy_score, privacy_mode)
