import re
import json
import sys
import os
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError
import time

# LangChain and Groq imports
try:
    from langchain_groq import ChatGroq
    from langchain_core.prompts import ChatPromptTemplate
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("[WARN] LangChain/Groq not available. Install with: pip install langchain-groq")

# Vulnerable patterns to check for in the source code
# These patterns check for vulnerable versions in script tags, URLs, and source code
VULNERABLE_PATTERNS = {
    # Next.js < 13
    "nextjs_old": r"(?:_next/static/|next\.js[^/]*?@?)(1\.[0-9]\.|^1[0-2]\.)",
    
    # AngularJS 1.x
    "angularjs_v1_5": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.5",
    "angularjs_v1_4": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.4",
    "angularjs_v1_3": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.3",
    "angularjs_v1_2": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.2",
    "angularjs_v1_1": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.1",
    "angularjs_v1_0": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.0",
    "angularjs_old": r"angular(?:js)?(?:-|\.min)?\.js\?v?=1\.[0-6]",
    
    # jQuery < 1.12
    # Strict match for jquery file pattern, not just 'jquery' word
    "jquery_old": r"jquery[.-](?:1\.([0-9]|1[0-1]))(?:\.|\b)",
    
    # Bootstrap < 3.5
    "bootstrap_old": r"bootstrap(?:-|\.min)?\.(?:js|css)[^/]*?3\.[0-4]",
    
    # React < 16.8
    "react_old": r"react(?:-dom)?(?:-|\.min)?\.js[^/]*?(?:0\.|1[0-5]\.|16\.[0-7]\b)",
    
    # Vue.js < 2.6
    "vue_old": r"vue(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.[0-5])",
    
    # Backbone.js < 1.4
    "backbone_old": r"backbone(?:-|\.min)?\.js[^/]*?(?:0\.|1\.[0-3])",
    
    # Ember.js < 2.18
    # Strict boundary to avoid 'emberSupport' etc
    "ember_old": r"\bember(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.[0-1][0-7])",
    
    # Knockout.js < 3.5
    "knockout_old": r"knockout(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.|3\.[0-4])",
    
    # Dojo Toolkit < 1.14
    "dojo_old": r"dojo(?:-|\.min)?\.js[^/]*?(?:0\.|1\.[0-1][0-3])",
    
    # Prototype.js < 1.7.3
    "prototype_old": r"prototype(?:-|\.min)?\.js[^/]*?(?:0\.|1\.[0-6]\.|1\.7\.[0-2])",
    
    # MooTools < 1.6
    "mootools_old": r"mootools(?:-|\.min)?\.js[^/]*?(?:0\.|1\.[0-5])",
    
    # YUI < 3.18
    "yui_old": r"yui(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.|3\.[0-1][0-7])",
    
    # ExtJS < 6.2
    "extjs_old": r"ext(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.|3\.|4\.|5\.|6\.[0-1])",
    
    # Underscore.js < 1.9
    "underscore_old": r"underscore(?:-|\.min)?\.js[^/]*?(?:0\.|1\.[0-8])",
    
    # Lodash < 4.17
    "lodash_old": r"lodash(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.|3\.|4\.[0-1][0-6])",
    
    # jQuery UI < 1.12
    "jquery_ui_old": r"jquery-ui(?:-|\.min)?\.js[^/]*?(?:0\.|1\.[0-1][0-1])",
    
    # WordPress - look for generator tag or explicit wp-includes path with version
    "wordpress_old": r"wp-includes/.*?ver=(?:[0-4]\.|5\.[0-9]\.|6\.[0-1]\.)",
    
    # Drupal < 8
    "drupal_old": r"drupal\.js.*?v?(?:[0-7]\.)",
    
    # Joomla < 3.9
    "joomla_old": r"joomla.*?v?(?:[0-2]\.|3\.[0-8])",
    
    # Handlebars < 4.0
    "handlebars_old": r"handlebars(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.|3\.)",
    
    # Mustache.js < 3.0
    "mustache_old": r"mustache(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.)",
    
    # Marionette.js < 4.0
    "marionette_old": r"marionette(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.|3\.)",
    
    # RequireJS < 2.3
    "requirejs_old": r"require(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.[0-2])",
    
    # Socket.io < 2.0
    "socketio_old": r"socket\.io(?:-|\.min)?\.js[^/]*?(?:0\.|1\.)",
    
    # Modernizr < 3.0
    "modernizr_old": r"modernizr(?:-|\.min)?\.js[^/]*?(?:0\.|1\.|2\.)",
}


def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return url


# Technology detection patterns (broader than vulnerability patterns)
TECH_DETECTION_PATTERNS = {
    "angularjs": r"angular(?:js|\.js|\.min\.js)",
    "angular": r"@angular/|angular\.js|angularjs",
    "react": r"react(?:\.js|\.min\.js|/)|react-dom",
    "vue": r"vue(?:\.js|\.min\.js|\.runtime)",
    "nextjs": r"_next/|next\.js|__next",
    "nuxt": r"_nuxt/|nuxt\.js",
    "svelte": r"svelte|svelte\.js",
    "jquery": r"jquery(?:\.min)?\.js",
    "backbone": r"backbone(?:\.min)?\.js",
    "ember": r"ember(?:\.js|\.min\.js)",
    "knockout": r"knockout(?:\.min)?\.js",
    "dojo": r"dojo(?:\.js|\.min\.js)",
    "prototype": r"prototype(?:\.js|\.min\.js)",
    "mootools": r"mootools(?:\.js|\.min\.js)",
    "yui": r"yui(?:\.js|\.min\.js)",
    "extjs": r"ext(?:\.js|\.min\.js)",
    "underscore": r"underscore(?:\.min)?\.js",
    "lodash": r"lodash(?:\.min)?\.js",
    "moment": r"moment(?:\.min)?\.js",
    "jquery_ui": r"jquery-ui|jqueryui",
    "bootstrap": r"bootstrap(?:\.min)?\.(?:js|css)",
    "wordpress": r"wp-content|wp-includes|wp-admin|wordpress",
    "drupal": r"drupal\.js|sites/default",
    "joomla": r"joomla|components/com_",
    "magento": r"magento|skin/frontend",
    "shopify": r"cdn\.shopify|shopify",
    "woocommerce": r"woocommerce",
    "aspnet": r"asp\.net|aspx|viewstate|__doPostBack",
    "php": r"\.php\?|x-powered-by.*php",
    "rails": r"ruby.*on.*rails",  # Removed loose "rails"
    "django": r"csrfmiddlewaretoken", # Removed loose "django"
    "laravel": r"laravel|_token",
    "express": r"express\.js", # Removed loose "express"
    "socketio": r"socket\.io",
    "handlebars": r"handlebars(?:\.min)?\.js",
    "mustache": r"mustache(?:\.min)?\.js",
    "marionette": r"marionette(?:\.min)?\.js",
    "requirejs": r"require(?:\.min)?\.js",
    "fontawesome": r"font-awesome|fontawesome",
    "modernizr": r"modernizr(?:\.min)?\.js",
}



def detect_technologies_via_browser(page):
    """
    Detect technologies by injecting JavaScript into the page
    to check global variables and DOM attributes.
    This is much more accurate for version detection.
    """
    return page.evaluate("""() => {
        const techs = [];
        const seen = new Set();
        
        // Helper to add tech
        const add = (name, version, confidence='high') => {
            const key = name + ':' + (version || '');
            if (!seen.has(key)) {
                techs.push({name, version: version || null, confidence});
                seen.add(key);
            }
        };
        
        try {
            // jQuery
            if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
                add('jquery', window.jQuery.fn.jquery);
            }
            
            // AngularJS
            if (window.angular && window.angular.version) {
                 add('angularjs', window.angular.version.full);
            }
            
            // React Improved Detection
            // 1. Check for React Fiber keys
            let foundReact = false;
            
            const isReactElement = (el) => {
                 if (!el) return false;
                 return Object.keys(el).some(key => 
                    key.startsWith('__reactFiber') || 
                    key.startsWith('__reactInternalInstance') || 
                    key.startsWith('__reactContainer') ||
                    key.startsWith('_reactRootContainer')
                 );
            };
            
            if (isReactElement(document.body)) foundReact = true;
            if (!foundReact) {
                for (const child of document.body.children) {
                    if (isReactElement(child)) { foundReact = true; break; }
                }
            }
            if (!foundReact) {
                const roots = ['root', 'app', '__next', 'main'];
                for (const id of roots) {
                    const el = document.getElementById(id);
                    if (isReactElement(el)) { foundReact = true; break; }
                }
            }

            // Try to get React Version from DevTools Hook (works in many production apps)
            let reactVersion = null;
            if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers) {
                try {
                    const renderers = window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
                    // renderers is a Map or Object
                    if (renderers instanceof Map) {
                        for (const r of renderers.values()) {
                            if (r.version) { reactVersion = r.version; break; }
                        }
                    } else if (typeof renderers === 'object') {
                        for (const key in renderers) {
                            if (renderers[key] && renderers[key].version) {
                                reactVersion = renderers[key].version;
                                break;
                            }
                        }
                    }
                } catch(e) {}
            }

            if (reactVersion) {
                add('react', reactVersion, 'high');
            } else if (foundReact) {
                add('react', null, 'high');
            } else if (window.React && window.React.version) {
                add('react', window.React.version, 'high');
            } else if (document.querySelector('[data-reactroot], [data-reactid]')) {
                add('react', null, 'high');
            } else if (window.__NEXT_DATA__ || window.__NUXT__ || window.next) {
                 if (window.__NEXT_DATA__ || window.next) add('react', null, 'high');
            }
            
            // Next.js
            if (window.__NEXT_DATA__) {
                add('nextjs', null, 'high'); 
            }
            else if (window.next && window.next.version) {
                 add('nextjs', window.next.version, 'high');
            }
            
            // Nuxt.js
            if (window.__NUXT__) {
                add('nuxt', null, 'high');
            }
            
            // Bootstrap
            // Check for JS object - Downgraded to medium confidence to let Frameworks win
            if (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) {
                add('bootstrap', window.bootstrap.Tooltip.VERSION, 'medium');
            }
            
            // Lodash / Underscore
            if (window._ && window._.VERSION) {
                if (window._.templateSettings) {
                    add('underscore', window._.VERSION, 'medium');
                } else {
                    add('lodash', window._.VERSION, 'medium');
                }
            }
            
            // Moment.js
            if (window.moment && window.moment.version) {
                add('moment', window.moment.version, 'medium');
            }
            
            // Socket.io
            if (window.io && window.io.version) {
                add('socketio', window.io.version, 'medium');
            }
            
            // Meta Generator Tags (WordPress, Drupal, Joomla, etc.)
            const metas = document.querySelectorAll('meta[name="generator"]');
            metas.forEach(meta => {
                const content = meta.content.toLowerCase();
                if (content.includes('wordpress')) {
                    const match = content.match(/wordpress\s+(\d+\.\d+(?:\.\d+)?)/);
                    add('wordpress', match ? match[1] : null, 'high');
                }
                if (content.includes('drupal')) add('drupal', null, 'high');
                if (content.includes('joomla')) add('joomla', null, 'high');
                if (content.includes('shopify')) add('shopify', null, 'high');
                if (content.includes('magento')) add('magento', null, 'high');
                if (content.includes('wix')) add('wix', null, 'high');
                if (content.includes('squarespace')) add('squarespace', null, 'high');
            });
            
            // Script SRC scanning
            // Look for patterns like /jquery-3.6.0.min.js
            const scripts = document.querySelectorAll('script[src]');
            scripts.forEach(script => {
                const src = script.src;
                // Regex to capture filename and version
                // Matches: jquery-3.6.0.min.js, app.v1.2.3.js, etc.
                const match = src.match(/([a-zA-Z0-9-]+)[.-](\d+\.\d+(?:\.\d+)?)/);
                if (match) {
                    let name = match[1].toLowerCase();
                    const version = match[2];
                    
                    // Normalize common library names from filenames
                    if (name.includes('jquery') && !name.includes('ui')) name = 'jquery';
                    else if (name.includes('bootstrap')) name = 'bootstrap';
                    else if (name.includes('vue')) name = 'vue';
                    else if (name.includes('react')) name = 'react';
                    else if (name.includes('angular')) name = 'angular';
                    
                    if (['jquery', 'bootstrap', 'vue', 'react', 'angular', 'angularjs', 'moment', 'lodash', 'underscore', 'backbone', 'knockout'].includes(name)) {
                        add(name, version, 'medium');
                    }
                }
            });

        } catch (e) {
            // console.log('Tech detection error', e);
        }
        
        return techs;
    }""")


def detect_technologies_static(html_content):
    """
    Detect technologies from HTML content using regex.
    Improved to look for versions in context rather than globally.
    """
    html_lower = html_content.lower()
    detected_techs = []
    
    for tech_name, pattern in TECH_DETECTION_PATTERNS.items():
        # Find all matches of the tech pattern
        for match in re.finditer(pattern, html_lower, re.IGNORECASE):
            # Extract a window of text around the match to look for a version number
            # Look ahead ~30 chars and behind ~10 chars
            start_pos = match.start()
            end_pos = min(len(html_lower), match.end() + 30)
            
            context = html_lower[start_pos:end_pos]
            
            # Look for version pattern like "1.2.3" or "v1.2" inside this context
            # We want to be reasonably close to the tech name
            version_match = re.search(r'[v\s\/-](\d+\.\d+(?:\.\d+)?)', context)
            
            version = None
            if version_match:
                version = version_match.group(1)
            
            # If we found it, add it
            detected_techs.append({
                "name": tech_name,
                "version": version,
                "confidence": "low"  # Static analysis is always lower confidence than runtime
            })
            
            if version:
                break # If we found a versioned instance, likely good enough for this tech
    
    return detected_techs


def merge_detected_techs(browser_techs, static_techs):
    """
    Merge technologies detected from browser (high confidence) 
    and static analysis (low confidence).
    """
    merged = {}
    
    # Process browser techs first (higher priority)
    for tech in browser_techs:
        name = tech['name']
        version = tech['version']
        
        if name not in merged:
            merged[name] = version
        elif version and not merged[name]:
            # Upgrade to versioned if we only had unversioned
            merged[name] = version
            
    # Process static techs (fallback)
    for tech in static_techs:
        name = tech['name']
        version = tech['version']
        
        if name not in merged:
            merged[name] = version
        elif version and not merged[name]:
            # Upgrade to versioned if we only had unversioned
            merged[name] = version
            
    # Convert back to list format
    result = []
    for name, version in merged.items():
        result.append({"name": name, "version": version})
        
    return result


def format_tech_name(vulnerabilities, detected_techs=None):
    """Format technology name from vulnerabilities list or detected technologies."""
    # Map tech types to readable names
    tech_map = {
        "angularjs": "AngularJS",
        "angular": "Angular",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "react": "React",
        "vue": "Vue.js",
        "nextjs": "Next.js",
        "nuxt": "Nuxt.js",
        "svelte": "Svelte",
        "backbone": "Backbone.js",
        "ember": "Ember.js",
        "knockout": "Knockout.js",
        "dojo": "Dojo Toolkit",
        "prototype": "Prototype.js",
        "mootools": "MooTools",
        "yui": "YUI",
        "extjs": "ExtJS",
        "underscore": "Underscore.js",
        "lodash": "Lodash",
        "moment": "Moment.js",
        "jquery_ui": "jQuery UI",
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "magento": "Magento",
        "shopify": "Shopify",
        "woocommerce": "WooCommerce",
        "aspnet": "ASP.NET",
        "php": "PHP",
        "rails": "Ruby on Rails",
        "django": "Django",
        "laravel": "Laravel",
        "handlebars": "Handlebars",
        "mustache": "Mustache.js",
        "marionette": "Marionette.js",
        "requirejs": "RequireJS",
        "socketio": "Socket.io",
        "express": "Express.js",
        "fontawesome": "Font Awesome",
        "modernizr": "Modernizr",
    }
    
    # Priority 1: Use detected technologies
    if detected_techs:
        # Prioritize frameworks over libraries but showing multiple is good
        priority_order = ["nextjs", "nuxt", "react", "vue", "angular", "angularjs", "svelte", 
                        "wordpress", "drupal", "joomla", "magento", "shopify", "rails", 
                        "django", "laravel", "aspnet", "php", "express", "ember", "backbone", 
                        "bootstrap", "jquery"] # added bootstrap/jquery to end of priority list to still show if relevant
        
        # Sort detected techs by confidence (high first), then by priority
        def get_sort_key(t):
            conf_score = 3 if t.get('confidence') == 'high' else (2 if t.get('confidence') == 'medium' else 1)
            priority_score = 0
            if t['name'] in priority_order:
                priority_score = len(priority_order) - priority_order.index(t['name'])
            return (conf_score, priority_score)
            
        sorted_techs = sorted(detected_techs, key=get_sort_key, reverse=True)
        
        # Collect top technologies (up to 3 distinct frameworks/libs)
        formatted_names = []
        for tech in sorted_techs:
            # Skip if we already have 3
            if len(formatted_names) >= 3:
                break
                
            name = tech_map.get(tech["name"], tech["name"].title())
            if tech["version"]:
                name = f"{name} {tech['version']}"
            
            # Avoid duplicates (e.g. React and React 16)
            if not any(name.split()[0] in curr for curr in formatted_names):
                formatted_names.append(name)
        
        if formatted_names:
            return ", ".join(formatted_names)
            
    # Priority 2: Use vulnerabilities as fallback
    if vulnerabilities:
        first_vuln = vulnerabilities[0]
        tech_type = first_vuln.get("type", "")
        version = first_vuln.get("version", "unknown")
        
        tech_name = "Unknown"
        for key, name in tech_map.items():
            if key in tech_type.lower():
                tech_name = name
                break
        
        if version != "unknown":
            tech_name = f"{tech_name} {version}"
        
        return tech_name
    
    return "Unknown"


def format_load_time(fcp_ms):
    """Format load time from milliseconds to seconds string."""
    if fcp_ms is None:
        return "N/A"
    seconds = fcp_ms / 1000.0
    return f"{seconds:.1f}s"


def diagnose_site(url):
    """
    Diagnose a website for console errors, load speed, and vulnerabilities.
    
    Returns a JSON object with:
    - url: The tested URL
    - console_errors: List of console error messages
    - first_contentful_paint_ms: FCP time in milliseconds
    - vulnerabilities: List of detected vulnerable patterns
    - status: Overall status (clean, at_risk, timeout, error)
    """
    result = {
        "url": url,
        "console_errors": [],
        "first_contentful_paint_ms": None,
        "vulnerabilities": [],
        "status": "unknown"
    }

    print(f"[INFO] Starting diagnosis for {url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Capture console errors
        def handle_console(msg):
            if msg.type == "error":
                error_text = msg.text
                # Also capture location if available
                location = ""
                if msg.location:
                    location = f" ({msg.location['url']}:{msg.location.get('lineNumber', '?')})"
                result["console_errors"].append(error_text + location)

        page.on("console", handle_console)

        html = ""
        detected_techs = []
        
        try:
            # Navigate - try networkidle first, fallback to domcontentloaded
            try:
                page.goto(url, wait_until="networkidle", timeout=30000)
                print("[INFO] Page loaded (networkidle)")
            except TimeoutError:
                # If networkidle times out, try domcontentloaded to at least get HTML
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    print("[INFO] Page loaded (domcontentloaded - partial)")
                except TimeoutError:
                    # Even if timeout, try to get whatever HTML is available
                    print("[WARN] Page load timeout, attempting to get HTML...")
                    pass

            # 1. Detect technologies via active Browser JS injection (Most accurate)
            try:
                browser_techs = detect_technologies_via_browser(page)
                print(f"[INFO] Browser-detected technologies: {[t['name'] + (' ' + t['version'] if t['version'] else '') for t in browser_techs]}")
            except Exception as e:
                print(f"[WARN] Browser tech detection failed: {e}")
                browser_techs = []

            # 2. Get HTML content for static analysis and vulnerability scanning
            try:
                html = page.content()
                
                # Detect technologies via static HTML analysis (Fallback)
                static_techs = detect_technologies_static(html)
                
                # Merge results
                detected_techs = merge_detected_techs(browser_techs, static_techs)
                
                if detected_techs:
                    print(f"[INFO] Final detected technologies: {[t['name'] + (' ' + t['version'] if t['version'] else '') for t in detected_techs[:5]]}")
            except Exception as e:
                print(f"[WARN] Could not get HTML content: {e}")
                # Use whatever we got from browser
                detected_techs = merge_detected_techs(browser_techs, [])

            # Wait a bit for performance entries to be available
            time.sleep(1)

            # Measure First Contentful Paint (FCP)
            fcp = page.evaluate("""
                () => {
                    return new Promise((resolve) => {
                        // Check if FCP is already available
                        const entries = performance.getEntriesByType('paint');
                        const fcpEntry = entries.find(entry => entry.name === 'first-contentful-paint');
                        
                        if (fcpEntry) {
                            resolve(Math.round(fcpEntry.startTime));
                        } else {
                            // Wait for FCP if not available yet
                            const observer = new PerformanceObserver((list) => {
                                const entries = list.getEntries();
                                const fcpEntry = entries.find(entry => entry.name === 'first-contentful-paint');
                                if (fcpEntry) {
                                    observer.disconnect();
                                    resolve(Math.round(fcpEntry.startTime));
                                }
                            });
                            
                            try {
                                observer.observe({ entryTypes: ['paint'] });
                                // Timeout after 5 seconds
                                setTimeout(() => {
                                    observer.disconnect();
                                    resolve(null);
                                }, 5000);
                            } catch (e) {
                                resolve(null);
                            }
                        }
                    });
                }
            """)

            result["first_contentful_paint_ms"] = fcp
            if fcp:
                print(f"[INFO] FCP: {fcp}ms")
            else:
                print("[WARN] FCP measurement unavailable")

            # Get page source for vulnerability scanning (if not already got)
            if not html:
                try:
                    html = page.content()
                except:
                    html = ""
            
            html_lower = html.lower() if html else ""

            # Track found vulnerabilities to avoid duplicates
            found_vulns = set()
            
            # Check for vulnerable patterns (check specific versions first, then generic)
            # Order matters: check specific versions before generic patterns
            pattern_order = sorted(VULNERABLE_PATTERNS.items(), 
                                 key=lambda x: ('old' in x[0], x[0]))
            
            for tech, pattern in pattern_order:
                # Use stricter regex finditer
                matches = re.finditer(pattern, html_lower, re.IGNORECASE)
                for match in matches:
                    # Extract version number from the match context
                    match_start = max(0, match.start() - 50)
                    match_end = min(len(html_lower), match.end() + 50)
                    context = html_lower[match_start:match_end]
                    
                    # Try to find version number in the context
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', context)
                    version = version_match.group(1) if version_match else "unknown"
                    
                    # Create a unique key for this vulnerability
                    # For AngularJS, use the actual version instead of pattern name
                    if 'angularjs' in tech:
                        vuln_key = f"angularjs_{version}"
                    elif 'jquery' in tech and 'ui' not in tech:
                        # Skip jQuery plugins (files that aren't jquery.js or jquery.min.js)
                        matched_text = html[match.start():match.end()][:100].lower()
                        # Only flag if it's actually jquery.js or jquery.min.js, not plugins
                        if not ('jquery.js' in matched_text or 'jquery.min.js' in matched_text or 
                                'jquery/' in matched_text or '/jquery' in matched_text):
                            continue
                        vuln_key = f"jquery_{version}"
                    elif 'wordpress' in tech or 'drupal' in tech or 'joomla' in tech:
                        # CMS frameworks - use tech name as key
                        vuln_key = tech
                    elif 'php' in tech or 'aspnet' in tech or 'rails' in tech or 'django' in tech:
                        # Backend frameworks - use tech name and version
                        vuln_key = f"{tech}_{version}" if version != "unknown" else tech
                    else:
                        # Other frameworks - use tech name and version
                        vuln_key = f"{tech}_{version}" if version != "unknown" else tech
                    
                    # Skip if we've already found this vulnerability
                    if vuln_key in found_vulns:
                        continue
                    
                    found_vulns.add(vuln_key)
                    
                    # Extract the actual matched text for reference
                    matched_text = html[match.start():match.end()][:100]  # First 100 chars
                    
                    result["vulnerabilities"].append({
                        "type": tech,
                        "version": version,
                        "matched_text": matched_text
                    })
                    print(f"[WARN] Found vulnerability: {tech} (version: {version})")
                    break  # Only report once per pattern type

            # Determine overall status
            if result["console_errors"] or result["vulnerabilities"]:
                result["status"] = "at_risk"
            elif fcp and fcp > 3000:  # FCP > 3 seconds is considered slow
                result["status"] = "at_risk"
            else:
                result["status"] = "clean"

            print(f"[INFO] Status: {result['status']}")
            if result["console_errors"]:
                print(f"[INFO] Found {len(result['console_errors'])} console errors")
            if result["vulnerabilities"]:
                print(f"[INFO] Found {len(result['vulnerabilities'])} vulnerabilities")

        except TimeoutError:
            print("[ERROR] Page load timeout")
            result["status"] = "timeout"
            result["error"] = "Page load timeout after 30 seconds"
            # Try to get HTML even on timeout for tech detection
            try:
                html = page.content()
                static_techs = detect_technologies_static(html)
                detected_techs = merge_detected_techs([], static_techs)
                if detected_techs:
                    print(f"[INFO] Detected technologies (timeout): {[t['name'] for t in detected_techs[:3]]}")
            except:
                pass

        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            # Try to get HTML even on error for tech detection
            try:
                html = page.content()
                static_techs = detect_technologies_static(html)
                detected_techs = merge_detected_techs([], static_techs)
            except:
                pass

        finally:
            browser.close()

    # Add new fields to result
    result["domain"] = extract_domain(url)
    result["tech"] = format_tech_name(result["vulnerabilities"], detected_techs)
    result["console_error_count"] = len(result["console_errors"])
    result["load_time"] = format_load_time(result["first_contentful_paint_ms"])
    result["vulnerability_detected"] = len(result["vulnerabilities"]) > 0

    return result


def generate_technical_observation(result):
    """
    Generate a technical observation using Groq/LangChain.
    
    Args:
        result: Diagnosis result dictionary
    
    Returns:
        Technical observation string or None if generation fails
    """
    if not LANGCHAIN_AVAILABLE:
        return None
    
    # Get Groq API key from environment
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        print("[WARN] GROQ_API_KEY not set. Skipping technical observation generation.")
        return None
    
    try:
        # Extract data from result
        tech = result.get("tech", "Unknown")
        error_count = result.get("console_error_count", 0)
        load_time = result.get("load_time", "N/A")
        
        # Create the LLM
        llm = ChatGroq(
            groq_api_key=groq_api_key,
            model_name="llama-3.3-70b-versatile",
            temperature=0.3
        )
        
        # Create the prompt template with exact system prompt as specified
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a Senior Technical Architect. You are analyzing a prospective client's website.

They are running {tech} which is End-of-Life.

They have {error_count} console errors and a load time of {load_time}.

Write a specific, 2-sentence 'Technical Observation' about why this is dangerous for their business (focus on security or lost revenue). Do NOT be salesy. Be clinical."""),
            ("human", "Generate the technical observation.")
        ])
        
        # Create the chain
        chain = prompt | llm
        
        # Generate the observation
        print("[INFO] Generating technical observation with Groq...")
        response = chain.invoke({
            "tech": tech,
            "error_count": error_count,
            "load_time": load_time
        })
        
        observation = response.content.strip()
        print(f"[INFO] Technical observation generated")
        return observation
        
    except Exception as e:
        print(f"[ERROR] Failed to generate technical observation: {e}")
        return None


def diagnose_multiple_sites(urls, generate_observations=True):
    """
    Diagnose multiple websites and return results for each.
    
    Args:
        urls: List of URLs to diagnose
        generate_observations: Whether to generate technical observations using Groq
    
    Returns:
        List of diagnosis results (JSON objects)
    """
    results = []
    for url in urls:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        result = diagnose_site(url)
        
        # Generate technical observation if requested and vulnerabilities detected
        if generate_observations and result.get("vulnerability_detected", False):
            observation = generate_technical_observation(result)
            if observation:
                result["technical_observation"] = observation
        
        results.append(result)
        print()  # Empty line between results
    
    return results


if __name__ == "__main__":
    # Default URL if none provided
    TARGET_URLS = ["https://algofolks.com/"]
    
    # Allow URLs to be passed as command line arguments
    if len(sys.argv) > 1:
        TARGET_URLS = sys.argv[1:]
    
    print("=" * 60)
    print("Website Diagnosis Tool")
    print("=" * 60)
    print(f"Checking {len(TARGET_URLS)} domain(s)...\n")
    
    # Diagnose all sites
    all_results = diagnose_multiple_sites(TARGET_URLS)
    
    # Output JSON results
    print("\n" + "=" * 60)
    print("FINAL RESULTS (JSON)")
    print("=" * 60)
    
    if len(all_results) == 1:
        # Single result - output as single object
        print(json.dumps(all_results[0], indent=2))
    else:
        # Multiple results - output as array
        print(json.dumps(all_results, indent=2))
    
    # Also save to file
    output_file = "diagnosis_results.json"
    with open(output_file, 'w') as f:
        if len(all_results) == 1:
            json.dump(all_results[0], f, indent=2)
        else:
            json.dump(all_results, f, indent=2)
    
    print(f"\n[INFO] Results also saved to {output_file}")


