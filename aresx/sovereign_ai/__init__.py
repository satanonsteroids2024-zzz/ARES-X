"""ARES X v10 — compat shim for moved package aresx.sovereign_ai."""
from __future__ import annotations
# forwards 18 public symbols
from aresx.domains.ai.sovereign_cluster import ClusterMode  # noqa: F401
from aresx.domains.ai.sovereign_cluster import ComputeBudget  # noqa: F401
from aresx.domains.ai.sovereign_cluster import FineTuneJob  # noqa: F401
from aresx.domains.ai.sovereign_cluster import FineTuningPipeline  # noqa: F401
from aresx.domains.ai.sovereign_cluster import HardwareProfile  # noqa: F401
from aresx.domains.ai.sovereign_cluster import InferenceAPI  # noqa: F401
from aresx.domains.ai.sovereign_cluster import ModelInfo  # noqa: F401
from aresx.domains.ai.sovereign_cluster import ModelRegistry  # noqa: F401
from aresx.domains.ai.__init__ import PHASE_STATUS  # noqa: F401
from aresx.domains.ai.sovereign_cluster import SovereignCluster  # noqa: F401
from aresx.domains.ai.sovereign_cluster import TITAN_ROUTING  # noqa: F401
from aresx.domains.ai.sovereign_cluster import compute_budget  # noqa: F401
from aresx.domains.ai.sovereign_cluster import detect_hardware  # noqa: F401
from aresx.domains.ai.sovereign_cluster import fine_tuning  # noqa: F401
from aresx.domains.ai.sovereign_cluster import inference_api  # noqa: F401
from aresx.domains.ai.sovereign_cluster import logger  # noqa: F401
from aresx.domains.ai.sovereign_cluster import model_registry  # noqa: F401
from aresx.domains.ai.sovereign_cluster import sovereign_cluster  # noqa: F401
