"""Fixed standalone queue. Changing this file does not add the other engine."""
MATCH_MODE = 'BR'
MODE_LABEL = 'BR RANK'
WORKER_FILE = 'br_worker.py'
ENGINE_MODULE = 'br_engine'
MODE_ALIASES = ('1', 'BR', 'BR RANK', 'BR_RANK', 'BR-RANK', 'BRRANK')


def require_mode(value=None):
    mode = MATCH_MODE if value is None else str(value).strip().upper()
    if mode not in MODE_ALIASES:
        raise ValueError('This standalone build only supports ' + MODE_LABEL)
    return MATCH_MODE
