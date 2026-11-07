from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

def analyze_evtx(filepath):
    """Parses Windows Event Log (.evtx) files."""
    events = []
    try:
        # Read the EVTX file
        with Evtx(filepath) as log:
            for record in log.records():
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                
                # The XML namespace for Windows Events
                ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                
                system = root.find('ns:System', ns)
                if system is not None:
                    # Extract Event ID
                    event_id = system.find('ns:EventID', ns)
                    event_id_text = event_id.text if event_id is not None else "Unknown"
                    
                    # Extract Timestamp
                    time_created = system.find('ns:TimeCreated', ns)
                    timestamp = time_created.attrib.get('SystemTime') if time_created is not None else "Unknown"
                    
                    # Extract Provider/App name
                    provider = system.find('ns:Provider', ns)
                    provider_name = provider.attrib.get('Name') if provider is not None else "Unknown"

                    events.append({
                        "EventID": event_id_text,
                        "TimeCreated": timestamp,
                        "Provider": provider_name
                    })
                    
        # Return summary and the first 20 events for preview
        return {
            "Total Events Found": len(events),
            "Recent Events Preview": events[:20] 
        }
    except Exception as e:
        return {"Error": str(e)}