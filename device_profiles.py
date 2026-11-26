"""Reported match-login profiles based on lobe's declared profiles.

These are unverified reported values, not full fingerprints or real devices.
Memory and other fields not supplied by the source remain at existing defaults.
"""
# This is a reported protocol field, not the machine's network address.
DEFAULT_REPORTED_IP = '27.61.46.111'

PROFILES = {
    'lobe-realme-rmx2189': {
        'os': 'Android OS 10 / API-29 (QP1A.190711.020/1617006012)',
        'model': 'realme RMX2189', 'gpu': 'PowerVR Rogue GE8320',
        'resolution': (1600, 720), 'dpi': '320',
        'cpu': 'ARM64 FP ASIMD AES | 2301 | 8',
        'renderer': 'OpenGL ES 3.2 build 1.11@5425693',
    },
    'lobe-redmi-note10': {
        'os': 'Android OS 11 / API-30', 'model': 'Redmi Note 10',
        'gpu': 'Adreno (TM) 612', 'resolution': (2400, 1080), 'dpi': '440',
        'cpu': 'ARM64 FP ASIMD AES | 2200 | 8', 'renderer': 'OpenGL ES 3.2',
    },
    'lobe-samsung-a525f': {
        'os': 'Android OS 12 / API-31', 'model': 'Samsung SM-A525F',
        'gpu': 'Adreno (TM) 642L', 'resolution': (2400, 1080), 'dpi': '420',
        'cpu': 'ARM64 FP ASIMD AES | 2300 | 8', 'renderer': 'OpenGL ES 3.2',
    },
    'lobe-v2312': {
        'os': 'Android OS 13 / API-33', 'model': 'V2312', 'gpu': 'Mali-G57',
        'resolution': (2400, 1080), 'dpi': '440',
        'cpu': 'ARM64 FP ASIMD AES | 2400 | 8', 'renderer': 'OpenGL ES 3.2',
    },
}
