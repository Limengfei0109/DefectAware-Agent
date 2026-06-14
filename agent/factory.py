from typing import Dict, List

from .agent import DefectVerificationAgent
from .workflow import ControlledVerificationWorkflow


def build_verification_engine(
    llm_config: Dict,
    agent_config: Dict,
    libclang_path: str = "",
    compile_args: List[str] = None,
):
    if agent_config.get("mode") == "controlled_workflow":
        return ControlledVerificationWorkflow(
            llm_config, agent_config, libclang_path, compile_args
        )
    return DefectVerificationAgent(llm_config, agent_config, libclang_path, compile_args)
