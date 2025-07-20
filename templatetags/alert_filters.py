from django import template

register = template.Library()

@register.filter
def filter_by_severity(alerts, severity_level):
    """
    Filters a list of alerts by their 'severity' attribute.
    Assumes each alert in the list is an object or dictionary with a 'severity' key/attribute.
    """
    if not isinstance(alerts, (list, tuple)):
        return [] # Return empty if not an iterable

    filtered_alerts = []
    for alert in alerts:
        # Check if alert is a dictionary or an object with an attribute
        if isinstance(alert, dict) and 'severity' in alert and alert['severity'].lower() == severity_level.lower():
            filtered_alerts.append(alert)
        elif hasattr(alert, 'severity') and getattr(alert, 'severity').lower() == severity_level.lower():
            filtered_alerts.append(alert)
    return filtered_alerts