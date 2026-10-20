//! DOM XSS and sink monitoring for browser sessions.
//! Inject JavaScript instrumentation to detect client-side vulnerabilities.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOMSinkEvent {
    pub sink_type: String, // "eval", "innerHTML", "postMessage", "location", etc.
    pub value: String,
    pub stack_trace: Option<String>,
    pub url: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOMMonitoringSession {
    pub session_id: i64,
    pub events: Vec<DOMSinkEvent>,
    pub findings: Vec<DOMFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DOMFinding {
    pub severity: String, // "high", "medium", "low"
    pub sink: String,
    pub value: String,
    pub description: String,
    pub url: String,
}

/// JavaScript injection code for DOM sink monitoring
pub const DOM_INSTRUMENTATION: &str = r#"
(function() {
    if (window.__HUNTPROXY_DOM_MONITOR__) return;
    window.__HUNTPROXY_DOM_MONITOR__ = true;

    const events = [];
    const MAX_EVENTS = 1000;

    function captureEvent(sinkType, value, stack) {
        if (events.length >= MAX_EVENTS) return;

        events.push({
            sink_type: sinkType,
            value: String(value).substring(0, 500),
            stack_trace: stack ? String(stack).substring(0, 1000) : null,
            url: window.location.href,
            timestamp: new Date().toISOString()
        });
    }

    // Hook eval
    const originalEval = window.eval;
    window.eval = function(code) {
        captureEvent('eval', code, new Error().stack);
        return originalEval.apply(this, arguments);
    };

    // Hook innerHTML
    const innerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (innerHTMLDesc && innerHTMLDesc.set) {
        const originalSet = innerHTMLDesc.set;
        innerHTMLDesc.set = function(value) {
            captureEvent('innerHTML', value, new Error().stack);
            return originalSet.call(this, value);
        };
        Object.defineProperty(Element.prototype, 'innerHTML', innerHTMLDesc);
    }

    // Hook document.write
    const originalWrite = document.write;
    document.write = function(content) {
        captureEvent('document.write', content, new Error().stack);
        return originalWrite.apply(this, arguments);
    };

    // Hook location changes
    const locationDesc = Object.getOwnPropertyDescriptor(window, 'location');
    ['href', 'search', 'hash'].forEach(prop => {
        const desc = Object.getOwnPropertyDescriptor(Location.prototype, prop);
        if (desc && desc.set) {
            const originalSet = desc.set;
            desc.set = function(value) {
                captureEvent('location.' + prop, value, new Error().stack);
                return originalSet.call(this, value);
            };
            Object.defineProperty(Location.prototype, prop, desc);
        }
    });

    // Hook postMessage
    const originalPostMessage = window.postMessage;
    window.postMessage = function(message, targetOrigin, transfer) {
        captureEvent('postMessage', JSON.stringify({message, targetOrigin}), new Error().stack);
        return originalPostMessage.apply(this, arguments);
    };

    // Hook setTimeout/setInterval with code strings
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(code, delay) {
        if (typeof code === 'string') {
            captureEvent('setTimeout', code, new Error().stack);
        }
        return originalSetTimeout.apply(this, arguments);
    };

    const originalSetInterval = window.setInterval;
    window.setInterval = function(code, delay) {
        if (typeof code === 'string') {
            captureEvent('setInterval', code, new Error().stack);
        }
        return originalSetInterval.apply(this, arguments);
    };

    // Expose getter for HuntProxy to retrieve events
    window.__HUNTPROXY_GET_EVENTS__ = function() {
        return events;
    };

    console.log('[HuntProxy] DOM sink monitoring active');
})();
"#;

/// Analyze DOM events for potential XSS
pub fn analyze_dom_events(events: &[DOMSinkEvent]) -> Vec<DOMFinding> {
    let mut findings = Vec::new();

    for event in events {
        let value_lower = event.value.to_lowercase();

        // Check for script tags
        if value_lower.contains("<script") {
            findings.push(DOMFinding {
                severity: "high".to_string(),
                sink: event.sink_type.clone(),
                value: event.value.clone(),
                description: format!("Script tag in {} sink - potential DOM XSS", event.sink_type),
                url: event.url.clone(),
            });
        }

        // Check for javascript: protocol
        if value_lower.contains("javascript:") {
            findings.push(DOMFinding {
                severity: "high".to_string(),
                sink: event.sink_type.clone(),
                value: event.value.clone(),
                description: format!("javascript: protocol in {} sink", event.sink_type),
                url: event.url.clone(),
            });
        }

        // Check for event handlers
        if value_lower.contains("onerror=")
            || value_lower.contains("onload=")
            || value_lower.contains("onclick=")
        {
            findings.push(DOMFinding {
                severity: "high".to_string(),
                sink: event.sink_type.clone(),
                value: event.value.clone(),
                description: format!("Event handler in {} sink - potential XSS", event.sink_type),
                url: event.url.clone(),
            });
        }

        // Check for eval with user input patterns
        if event.sink_type == "eval"
            && (value_lower.contains("window.location")
                || value_lower.contains("document.cookie")
                || value_lower.contains("localstorage"))
        {
            findings.push(DOMFinding {
                severity: "medium".to_string(),
                sink: "eval".to_string(),
                value: event.value.clone(),
                description: "eval() with sensitive data access".to_string(),
                url: event.url.clone(),
            });
        }

        // Check for postMessage to wildcard origin
        if event.sink_type == "postMessage" && value_lower.contains("\"*\"") {
            findings.push(DOMFinding {
                severity: "medium".to_string(),
                sink: "postMessage".to_string(),
                value: event.value.clone(),
                description: "postMessage to wildcard origin (*)".to_string(),
                url: event.url.clone(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_detection() {
        let events = vec![DOMSinkEvent {
            sink_type: "innerHTML".to_string(),
            value: "<script>alert(1)</script>".to_string(),
            stack_trace: None,
            url: "https://example.com".to_string(),
            timestamp: "2026-10-18T00:00:00Z".to_string(),
        }];

        let findings = analyze_dom_events(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert!(findings[0].description.contains("DOM XSS"));
    }

    #[test]
    fn test_javascript_protocol() {
        let events = vec![DOMSinkEvent {
            sink_type: "location.href".to_string(),
            value: "javascript:alert(1)".to_string(),
            stack_trace: None,
            url: "https://example.com".to_string(),
            timestamp: "2026-10-18T00:00:00Z".to_string(),
        }];

        let findings = analyze_dom_events(&events);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("javascript: protocol"));
    }
}
