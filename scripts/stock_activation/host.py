"""Host interface. All effects go through Host. Live variant refuses."""

from scripts.stock_activation.states import JOURNAL_DIR


class Host:
    def journal_load(self):
        raise NotImplementedError

    def journal_append(self, state, detail=None):
        raise NotImplementedError

    def journal_dir_info(self):
        raise NotImplementedError

    def boot_id(self):
        raise NotImplementedError

    def show_unit(self, unit):
        raise NotImplementedError

    def stop_units(self, units):
        raise NotImplementedError

    def start_units(self, units):
        raise NotImplementedError

    def reload_manager(self):
        raise NotImplementedError

    def read_bytes(self, path):
        raise NotImplementedError

    def file_info(self, path):
        raise NotImplementedError

    def write_temp(self, tmp_path, data):
        raise NotImplementedError

    def file_fsync(self, path):
        raise NotImplementedError

    def rename_path(self, src, dst):
        raise NotImplementedError

    def dir_fsync(self, dir_path):
        raise NotImplementedError

    def now(self):
        raise NotImplementedError

    def sleep_secs(self, seconds):
        raise NotImplementedError

    def proc_identity(self, pid):
        raise NotImplementedError

    def denial_probe(self, path):
        raise NotImplementedError

    def python_probe(self, python_exe):
        raise NotImplementedError

    def backup_ok(self):
        raise NotImplementedError

    def digest_record(self):
        raise NotImplementedError

    def dashboard_fetch(self, url, headers):
        raise NotImplementedError

    def gateway_talk(self, request_bytes):
        raise NotImplementedError

    def dropin_names(self, service):
        raise NotImplementedError

    def file_uid(self, path):
        raise NotImplementedError


class LiveRootHost(Host):
    """Present only behind refusal. Never used by tests or CLI."""

    _refusal = "ACTIVATION_NOT_AUTHORIZED"

    def _refuse(self):
        raise RuntimeError(self._refusal)

    def journal_load(self):
        self._refuse()

    def journal_append(self, state, detail=None):
        self._refuse()

    def journal_dir_info(self):
        self._refuse()

    def boot_id(self):
        self._refuse()

    def show_unit(self, unit):
        self._refuse()

    def stop_units(self, units):
        self._refuse()

    def start_units(self, units):
        self._refuse()

    def reload_manager(self):
        self._refuse()

    def read_bytes(self, path):
        self._refuse()

    def file_info(self, path):
        self._refuse()

    def write_temp(self, tmp_path, data):
        self._refuse()

    def file_fsync(self, path):
        self._refuse()

    def rename_path(self, src, dst):
        self._refuse()

    def dir_fsync(self, dir_path):
        self._refuse()

    def now(self):
        self._refuse()

    def sleep_secs(self, seconds):
        self._refuse()

    def proc_identity(self, pid):
        self._refuse()

    def denial_probe(self, path):
        self._refuse()

    def python_probe(self, python_exe):
        self._refuse()

    def backup_ok(self):
        self._refuse()

    def digest_record(self):
        self._refuse()

    def dashboard_fetch(self, url, headers):
        self._refuse()

    def gateway_talk(self, request_bytes):
        self._refuse()

    def dropin_names(self, service):
        self._refuse()

    def file_uid(self, path):
        self._refuse()
