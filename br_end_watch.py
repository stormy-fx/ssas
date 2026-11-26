"""Local BR receive deadlines and redacted waiting diagnostics, not an end oracle.

No socket, wall-clock, account ID, position, packet body or credential is stored
here. Cmd103/4 acceptance and exact-self107 semantics remain in the receiver.
"""
from br_lifecycle import _seconds
import br_lifecycle_config as config


class BrEndWatch:
    def __init__(self, started_mono, *, idle_seconds=None, maximum_seconds=None,
                 status_interval_seconds=None, layout_source='unknown'):
        # Fixed labels only: never retain/print a supplied layout, identifier,
        # packet bytes or arbitrary caller-supplied text.
        self.layout_source = (layout_source if type(layout_source) is str and
                              layout_source in ('assignment', 'fallback') else 'unknown')
        self.started = _seconds(started_mono, 'started_mono')
        self.last_valid = self.started
        self.last_self = None
        self.last_report = self.started
        self.idle = _seconds(config.UDP_IDLE_TIMEOUT_SECONDS if idle_seconds is None else idle_seconds,
                             'UDP_IDLE_TIMEOUT_SECONDS', positive=True)
        self.maximum = _seconds(config.MAX_SESSION_SECONDS if maximum_seconds is None else maximum_seconds,
                                'MAX_SESSION_SECONDS', positive=True)
        self.interval = _seconds(config.END_STATUS_INTERVAL_SECONDS if status_interval_seconds is None
                                 else status_interval_seconds, 'END_STATUS_INTERVAL_SECONDS')
        self.end103 = self.disconnect4 = self.death107 = 0
        self.end_bad_crc = self.end_prestart = 0
        self.unmatched107 = self.self107 = 0
        # These are header-only candidates with undecryptable bodies, NOT
        # death/end/revive signals. No packet, identity or key is retained.
        self.opaque = {command: 0 for command in (4, 101, 103, 107, 139, 256, 393)}

    def note_opaque_header(self, command):
        if type(command) is int and command in self.opaque:
            self.opaque[command] += 1

    def note_frame(self, command, now, *, crc_ok, startup_sent):
        # Caller has already enforced the assigned endpoint. A bad-CRC header
        # is counted as rejected, not trusted as a real server end command.
        end_candidate = type(command) is int and command in (4, 103)
        if not crc_ok:
            if end_candidate:
                self.end_bad_crc += 1
            return
        self.last_valid = float(now)
        if type(command) is not int:
            return
        if command == 103:
            self.end103 += 1
        elif command == 4:
            self.disconnect4 += 1
        elif command == 107:
            self.death107 += 1
        if end_candidate and not startup_sent:
            self.end_prestart += 1

    def self_state(self, now):
        # A position's arrival is diagnostic only, never proof of revival/end.
        self.last_self = float(now)

    def timeout_reason(self, now, *, startup_sent):
        if now - self.started >= self.maximum:
            return 'maximum_duration_unconfirmed'
        if startup_sent and now - self.last_valid >= self.idle:
            return 'udp_inactive'
        return None

    def receive_timeout(self, now, *, startup_sent, default):
        remaining = [float(default), self.started + self.maximum - now]
        if startup_sent:
            remaining.append(self.last_valid + self.idle - now)
        if self.interval:
            remaining.append(self.last_report + self.interval - now)
        return max(0.05, min(remaining))

    def report_due(self, now):
        if not self.interval or now < self.last_report + self.interval:
            return False
        self.last_report = float(now)
        return True

    def summary(self, now, *, tag, phase, startup_sent, seen_match_state, life,
                squad_lifecycle, udp_counts, reason=None):
        # Fixed labels/counters only; even arbitrary caller-supplied labels
        # cannot inject an account identifier, raw error, or multiline secret.
        tag = tag if tag in ('[M]', '[S1]', '[S2]', '[S3]') else '[?]'
        phases = {'not_started', 'waiting_for_hello_reply', 'ack_sent_waiting',
                  'ready_to_send_thunder', 'thunder_sharma_sent'}
        phase = phase if phase in phases else 'other'
        reasons = {'error', 'cancelled', 'udp_inactive', 'udp_disconnect', 'match_end_103',
                   'maximum_duration_unconfirmed', 'handshake_timeout', 'local_squad_death_107'}
        suffix = '' if reason is None else ' reason=' + (reason if reason in reasons else 'other')
        members = tuple(squad_lifecycle.members.values())
        total = len(members)
        dead = sum(bool(m.get('dead')) for m in members)
        closed = sum(m.get('ended') is not None for m in members)
        self_age = 'none' if self.last_self is None else f'{max(0.0, now-self.last_self):.1f}s'
        count = lambda key: max(0, int(udp_counts.get(key, 0)))
        return (f'[BR-WATCH] {tag} phase={phase}{suffix} layout_source={self.layout_source} '
                f'elapsed={max(0.0, now-self.started):.1f}s '
                f'rx_idle={max(0.0, now-self.last_valid):.1f}s self_age={self_age} '
                f'started={int(bool(startup_sent))} state_seen={int(bool(seen_match_state))} '
                f'self_id={int(life.join_identity is not None or life.echo_identity is not None)} '
                f'self_dead={int(life.inactive_107)} knocked={int(life.knocked)} '
                f'squad_dead={dead}/{total} squad_ended={closed}/{total} '
                f'rx={count("received")} wrong_source={count("wrong_source")} '
                f'undecodable={count("undecodable")} bad_crc={count("bad_crc")} '
                f'end103={self.end103} disconnect4={self.disconnect4} '
                f'death107={self.death107} self107={self.self107} unmatched107={self.unmatched107} '
                f'end_bad_crc={self.end_bad_crc} end_prestart={self.end_prestart} '
                f'opaque4={self.opaque[4]} opaque101={self.opaque[101]} '
                f'opaque103={self.opaque[103]} opaque107={self.opaque[107]} '
                f'opaque139={self.opaque[139]} opaque256={self.opaque[256]} opaque393={self.opaque[393]}')
