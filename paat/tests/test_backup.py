from types import SimpleNamespace

from panlab.backup import export_running_config, write_backup, xapi_xml_text


class FakeXapi:
    def __init__(self, result=None, document=None):
        self._result = result
        self.xml_document = document

    def export(self, category="configuration"):
        return None

    def xml_result(self):
        return self._result


def test_export_falls_back_to_xml_document_when_result_is_empty() -> None:
    fw = SimpleNamespace(xapi=FakeXapi(result=None, document='<config version="11.1.0"/>\n'))
    text = export_running_config(fw)
    assert text.startswith("<?xml")
    assert '<config version="11.1.0"/>' in text


def test_export_uses_xml_result_when_present() -> None:
    fw = SimpleNamespace(xapi=FakeXapi(result='<config version="11.1.0"/>', document="ignored"))
    text = export_running_config(fw)
    assert "<config version=\"11.1.0\"/>" in text


def test_xapi_xml_text_rejects_element_stringification() -> None:
    fw = SimpleNamespace(xapi=FakeXapi(result="<Element 'config' at 0xabc>", document=None))
    try:
        xapi_xml_text(fw)
    except RuntimeError as exc:
        assert "did not look like XML" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")


def test_write_backup_uses_sanitized_host(tmp_path) -> None:
    path = write_backup('<?xml version="1.0"?>\n<config/>\n', dest_dir=tmp_path, host="203.0.113.3")
    assert path.parent == tmp_path
    assert path.name.startswith("running-203.0.113.3-")
    assert path.suffix == ".xml"
    assert path.read_text(encoding="utf-8").startswith("<?xml")
