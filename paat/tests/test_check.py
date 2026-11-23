from pathlib import Path

from panlab.check import CheckResult, parse_system_info





def test_parse_system_info_from_xml_string() -> None:
    xml = """
    <response status="success">
      <result>
        <system>
          <hostname>fw-example-01</hostname>
          <model>PA-440</model>
          <sw-version>11.1.6-h40</sw-version>
        </system>
      </result>
    </response>
    """
    info = parse_system_info(xml)
    assert info.hostname == "fw-example-01"
    assert info.model == "PA-440"
    assert info.version == "11.1.6-h40"
    assert info.serial is None


def test_parse_system_info_from_show_system_info_dict() -> None:
    info = parse_system_info(
        {
            "system": {
                "hostname": "fw-example-01",
                "model": "PA-440",
                "sw-version": "11.1.6-h40",
                "serial": "000000000000",
            }
        }
    )
    assert info.hostname == "fw-example-01"
    assert info.model == "PA-440"
    assert info.version == "11.1.6-h40"


def test_check_result_text_uses_device_fields_not_api_host() -> None:
    result = CheckResult(
        host="203.0.113.3",
        auth="API key",
        hostname="fw-example-01",
        model="PA-440",
        version="11.1.6-h40",
    )
    text = result.to_text()
    assert "Connected to 203.0.113.3 using API key." in text
    assert "device hostname: fw-example-01" in text
    assert "model:           PA-440" in text
    assert "sw-version:      11.1.6-h40" in text
    assert "(unknown)" not in text
    assert "omitted" in text


def test_check_result_omits_serial_by_default() -> None:
    result = CheckResult(
        host="203.0.113.3",
        auth="API key",
        hostname="fw-example-01",
        model="PA-440",
        version="11.1.6-h40",
        serial="000000000000",
    )
    assert "000000000000" not in result.to_text()
    assert "000000000000" in result.to_text(show_serial=True)
