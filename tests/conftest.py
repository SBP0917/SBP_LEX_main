from __future__ import annotations

import os


# The impersonation module fixes its deployment mode at first import. Set the
# explicit non-production mode before pytest imports any indirect pipeline
# dependency so collection order cannot select production mode for test-only
# composition fixtures.
os.environ["SBP_LEX_IMPERSONATION_RUNTIME_MODE"] = "TEST_ONLY"
os.environ["SBP_LEX_AUTHORITY_PROVENANCE_RUNTIME_MODE"] = "TEST_ONLY"
