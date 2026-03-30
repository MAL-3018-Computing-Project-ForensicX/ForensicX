#!/usr/bin/env python3
"""
parse_evtx.py - Extended for Sysmon Network Events (EID 3)
"""

import json
import sys
import os
from lxml import etree
from Evtx.Evtx import Evtx

def extract_event_fields(event_xml):
    """Extract Sysmon event fields without breaking on namespaces."""
    try:
        xml = etree.fromstring(event_xml.encode("utf-8"))

        # EventID
        event_id_el = xml.find(".//{*}EventID")
        event_id = event_id_el.text if event_id_el is not None else None

        # TimeCreated
        time_el = xml.find(".//{*}TimeCreated")
        time = time_el.attrib.get("SystemTime") if time_el is not None else None

        # Collect <Data Name="...">value</Data>
        data = {}
        for d in xml.findall(".//{*}Data"):
            name = d.attrib.get("Name")
            value = d.text
            if name:
                data[name] = value

        return {
            "event_id": event_id,
            "time": time,
            "data": data
        }
    except Exception as e:
        print(f"[!] Error parsing event: {e}")
        return None


def parse_evtx(input_path, output_path, filter_ids=None):
    events = []
    try:
        with Evtx(input_path) as evtx:
            for record in evtx.records():
                ev = extract_event_fields(record.xml())
                if not ev:
                    continue
                if filter_ids and ev["event_id"] not in filter_ids:
                    continue
                events.append(ev)
    except Exception as e:
        print(f"[!] Error reading EVTX: {e}")

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(events, fh, indent=2)

    print(f"[+] Extracted {len(events)} events -> {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parse_evtx.py <input.evtx> <output.json> [filter_ids...]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    filter_ids = sys.argv[3:] if len(sys.argv) > 3 else None

    parse_evtx(input_file, output_file, filter_ids)
