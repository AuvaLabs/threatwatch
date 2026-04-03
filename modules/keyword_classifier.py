"""Zero-cost keyword-based article classifier.

Replaces the AI engine for classification, using regex patterns
to determine if an article is cybersecurity-related and categorize it.
No API calls — runs entirely locally.
"""

import re
import logging
import hashlib

from modules.ai_cache import get_cached_result, cache_result
from modules.config import MAX_CONTENT_CHARS

# Priority-ordered classification rules (first match wins)
_RULES = [
    {
        "category": "Zero-Day Exploit",
        "re": re.compile(
            r"zero.?day|0day|0-day|actively\s+exploited|in\s+the\s+wild"
            r"|no\s+patch\s+available|unpatched\s+vuln",
            re.IGNORECASE,
        ),
        "confidence": 90,
    },
    {
        "category": "Ransomware",
        "re": re.compile(
            r"ransomware|encrypted\s+files|ransom\s+demand|lockbit|blackcat"
            r"|cl0p|clop|akira\s+ransom|play\s+ransomware|alphv|rhysida"
            r"|medusa\s+ransom|black\s*basta|royal\s+ransom|hive\s+ransom"
            r"|conti\s+ransom|ransomhub|bianlian"
            # Newer ransomware groups (2024-2026)
            r"|hunters\s+international|qilin\s+ransom|agenda\s+ransom"
            r"|inc\s+ransom|incransom|embargo\s+ransom|interlock\s+ransom"
            r"|brain.?cipher|fog\s+ransom|lynx\s+ransom|safepay\s+ransom"
            r"|3am\s+ransom|three\s*am\s+ransom|dragonforce\s+ransom"
            r"|underground\s+team\s+ransom|abyss\s+locker|space\s+bears"
            r"|hellcat\s+ransom|cloak\s+ransom|eldorado\s+ransom"
            r"|beast\s+ransom|sarcoma\s+ransom|meow\s+ransom|cicada3301",
            re.IGNORECASE,
        ),
        "confidence": 92,
    },
    {
        "category": "Nation-State Attack",
        "re": re.compile(
            r"\bapt\d{1,3}\b|nation.?state|state.?sponsored|cyber\s*espionage"
            r"|lazarus|volt\s*typhoon|salt\s*typhoon|sandworm|fancy\s*bear"
            r"|cozy\s*bear|midnight\s*blizzard|charming\s*kitten|muddywater"
            r"|kimsuky|hidden\s*cobra|apt28|apt29|apt41|winnti|turla"
            r"|gamaredon|star\s*blizzard"
            # Additional APT groups and aliases (2024-2026)
            r"|scattered\s+spider|unc3944|silk\s+typhoon|forest\s+blizzard"
            r"|ghost\s*emperor|ghost\s*writer|goldenj\s*ackal|golden\s+jackal"
            r"|bluenoroff|andariel|lazarus\s+group|storm-\d{4}|storm\s+\d{4}"
            r"|earth\s+kasha|redjuliett|red\s+juliet|emerald\s+sleet"
            r"|jade\s+sleet|onyx\s+sleet|citrine\s+sleet|raspberry\s+robin"
            r"|damselfly|nespresso\s+malware|unc3886|unc2529"
            r"|hafnium|peach\s+sandstorm|mint\s+sandstorm|crimson\s+sandstorm"
            r"|seashell\s+blizzard|aqua\s+blizzard|cadet\s+blizzard",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Cyber Espionage",
        "re": re.compile(
            r"cyber\s*espionage|espionage\s+campaign|spying|intelligence\s+gathering"
            r"|surveillance\s+malware|state\s+actor",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Critical Infrastructure Attack",
        "re": re.compile(
            r"critical\s+infrastructure|power\s+grid|water\s+treatment"
            r"|pipeline\s+attack|energy\s+sector\s+attack|nuclear\s+facility"
            r"|dam\s+attack|electrical\s+grid",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Supply Chain Attack",
        "re": re.compile(
            r"supply[\s-]*chain\s*(attack|compromise|hack|breach)"
            r"|supply[\s-]*chain\b.*\b(malicious|exploit|compromise|backdoor|trojan)"
            r"|third.party\s+breach"
            r"|software\s+update.*compromis|dependency\s+confusion"
            r"|npm\s+(package\s+)?malicious|pypi\s+malicious|github\s+action\s+compromis"
            r"|open\s+vsx\s+extension|vscode\s+extension.*malicious",
            re.IGNORECASE,
        ),
        "confidence": 87,
    },
    {
        "category": "Data Breach",
        "re": re.compile(
            r"data\s+breach|breached|data\s+leak|leaked|exposed\s+data"
            r"|stolen\s+data|data\s+dump|database\s+exposed|records\s+stolen"
            r"|credentials\s+leaked|personal\s+data\s+exposed"
            r"|million\s+records|account.*compromis"
            r"|\bbreach\b(?!\s*(of\s+contract|of\s+trust|of\s+duty))"
            r"|source\s+code\s+(stolen|leaked|exposed)"
            r"|customer\s+(data|records?|info)\s+(stolen|leaked|exposed|at\s+risk)",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Malware",
        "re": re.compile(
            r"\bmalware\b|trojan|backdoor|\brat\b|stealer|infostealer"
            r"|loader|dropper|\bbotnet\b|\bworm\b|emotet|qakbot|trickbot"
            r"|cobalt\s*strike|sliver\s+c2|redline\s+stealer|raccoon"
            r"|bumblebee|icedid|lumma\s*stealer|vidar|amadey"
            r"|rootkit|spyware|keylogger|wiper|cryptojack",
            re.IGNORECASE,
        ),
        "confidence": 87,
    },
    {
        "category": "Cryptocurrency/Blockchain Theft",
        "re": re.compile(
            r"crypto\s*(theft|hack|heist|stolen)|bitcoin\s+stolen"
            r"|blockchain\s+hack|defi\s+exploit|exchange\s+hack"
            r"|wallet\s+drain|nft\s+scam|rug\s+pull|bridge\s+exploit",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Cloud Security Incident",
        "re": re.compile(
            r"cloud\s+breach|aws\s+(breach|exposed|misconfigur)"
            r"|azure\s+(breach|incident|vuln)|gcp\s+breach"
            r"|s3\s+bucket\s+exposed|container\s+escape|kubernetes\s+vuln",
            re.IGNORECASE,
        ),
        "confidence": 82,
    },
    {
        "category": "IoT/OT Security",
        "re": re.compile(
            r"\bics\b.*attack|\bscada\b|operational\s+technology"
            r"|\bot\s+security\b|\bot\s+attack\b|industrial\s+control"
            r"|plc\s+attack|smart\s+device\s+hack|iot\s+(attack|vuln|hack)",
            re.IGNORECASE,
        ),
        "confidence": 82,
    },
    {
        "category": "Account Takeover",
        "re": re.compile(
            r"account\s+takeover|credential\s+stuffing|brute\s+force\s+attack"
            r"|password\s+spray|sim\s+swap|mfa\s+bypass",
            re.IGNORECASE,
        ),
        "confidence": 80,
    },
    {
        "category": "Insider Threat",
        "re": re.compile(
            r"insider\s+threat|rogue\s+employee|disgruntled\s+worker"
            r"|employee\s+stole|internal\s+breach",
            re.IGNORECASE,
        ),
        "confidence": 78,
    },
    {
        "category": "DDoS",
        "re": re.compile(
            r"\bddos\b|denial\s+of\s+service|flood\s+attack"
            r"|bandwidth\s+attack|layer\s+7\s+attack|volumetric\s+attack",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Phishing",
        "re": re.compile(
            r"phishing|spearphish|credential\s+harvest|fake\s+login"
            r"|lookalike\s+domain|email\s+lure|smishing|vishing"
            r"|social\s+engineering\s+attack|business\s+email\s+compromise|\bbec\b",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Hacktivism",
        "re": re.compile(
            r"hacktivist|hacktivism|\banonymous\b.*hack|defacement"
            r"|politically\s+motivated\s+attack|cyber\s+protest",
            re.IGNORECASE,
        ),
        "confidence": 78,
    },
    {
        "category": "Disinformation/Influence Operation",
        "re": re.compile(
            r"disinformation|influence\s+operation|fake\s+news\s+campaign"
            r"|propaganda\s+cyber|troll\s+farm|information\s+warfare"
            r"|deepfake\s+attack",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    {
        "category": "Vulnerability Disclosure",
        "re": re.compile(
            r"cve-\d{4}|cvss\s+\d|vulnerability\s+discover"
            r"|vulnerability\s+disclos|\brce\b|remote\s+code\s+execution"
            r"|privilege\s+escalation|sql\s+injection|xss\s+vuln"
            r"|buffer\s+overflow|auth(entication)?\s+bypass"
            r"|vulnerabilit\w+\s+(let|allow|enable|could|in\s+\w)"
            r"|security\s+flaw|critical\s+flaw"
            r"|arbitrary\s+(command|code)\s+execution"
            r"|root\s+access\s+(flaw|vuln|exploit)"
            r"|\bexploit\w*\s+(flaw|bug|vuln)",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Patch/Security Update",
        "re": re.compile(
            r"patch\s+tuesday|security\s+patch|security\s+update"
            r"|hotfix|firmware\s+update|emergency\s+patch|out-of-band\s+patch"
            r"|security\s+advisory|critical\s+update"
            r"|patches\s+(partly\s+)?critical\s+vulnerabilit"
            r"|patches\s+.{0,20}(flaw|bug|issue|hole)",
            re.IGNORECASE,
        ),
        "confidence": 82,
    },
    {
        "category": "Security Policy/Regulation",
        "re": re.compile(
            r"cybersecurity\s+(regulation|law|policy|legislation|mandate|directive)"
            r"|gdpr\s+fine|sec\s+cyber|nist\s+framework|cyber\s+resilience\s+act"
            r"|executive\s+order.*cyber|cisa\s+directive",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    {
        "category": "Threat Research & Analysis",
        "re": re.compile(
            r"malware\s+analysis|reverse\s+engineer|dissecting\s+"
            r"|anatomy\s+of\s+(a|an|the)\s+"
            r"|deep\s+dive\s+into|technical\s+analysis"
            r"|exploit\s+chain|attack\s+chain|kill\s+chain\s+analysis"
            r"|proof[\s-]+of[\s-]+concept|\bpoc\b.*exploit"
            r"|write[\s-]*up|walkthrough.*vuln|walkthrough.*exploit"
            r"|case\s+study.*breach|case\s+study.*attack|case\s+study.*incident"
            r"|\bdfir\b|digital\s+forensic|forensic\s+analysis"
            r"|incident\s+response\s+report|post[\s-]*mortem.*attack"
            r"|ttp\s+analysis|mitre\s+att&ck\s+mapping|attack\s+technique"
            r"|campaign\s+analysis|intrusion\s+analysis|adversary\s+tradecraft"
            r"|root\s+cause\s+analysis.*cyber|malware\s+reverse"
            r"|unpacking\s+|deobfuscat|sandbox\s+analysis",
            re.IGNORECASE,
        ),
        "confidence": 80,
    },
    {
        "category": "Detection & Response",
        "re": re.compile(
            r"detection\s+engineering|detection\s+rule|detection\s+guide"
            r"|sigma\s+rule|yara\s+rule|snort\s+rule|suricata\s+rule"
            r"|threat\s+hunt|hunting\s+for\s+|hunting\s+guide"
            r"|incident\s+response\s+playbook|response\s+playbook"
            r"|blue\s+team|purple\s+team|soc\s+analyst\s+guide"
            r"|detection\s+strategy|detect\s+and\s+respond"
            r"|log\s+analysis.*attack|splunk\s+query.*detect"
            r"|kql\s+query.*detect|elastic\s+query.*detect"
            r"|defend\s+for\s+containers|container\s+attack\s+scenario"
            r"|forensic\s+investigation|memory\s+forensic"
            r"|network\s+forensic|disk\s+forensic",
            re.IGNORECASE,
        ),
        "confidence": 78,
    },
    {
        "category": "Threat Intelligence Report",
        "re": re.compile(
            r"threat\s+(report|landscape|brief|intelligence|research|analysis)"
            r"|security\s+report|cyber\s+threat\s+trend|annual\s+report.*cyber"
            r"|state\s+of\s+.*security|forecast.*cyber",
            re.IGNORECASE,
        ),
        "confidence": 72,
    },
    # ── Multi-language classification rules ──────────────────────────────
    # French
    {
        "category": "Ransomware",
        "re": re.compile(
            r"rançongiciel|rançon\s+numérique|chiffrement\s+des\s+données",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Data Breach",
        "re": re.compile(
            r"fuite\s+de\s+données|données\s+(exposées|volées|compromises)"
            r"|violation\s+de\s+données|patients?\s+exposée?s",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Nation-State Attack",
        "re": re.compile(
            r"cyberattaques?\s+massives?|attaque\s+étatique"
            r"|groupe\s+(Handala|APT|Lazarus|Sandworm)",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Critical Infrastructure Attack",
        "re": re.compile(
            r"cyberattaque\s+contre\s+.{0,30}(nucléaire|hôpital|infrastructure|énergie|central)"
            r"|infrastructure\s+critique\s+.{0,20}(attaque|compromise)",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Nation-State Attack",
        "re": re.compile(
            r"hackers?\s+iraniens?|hackers?\s+affiliés?\s+.{0,15}(Iran|Russie|Chine|Corée)"
            r"|hackers?\s+pro[\s-]+(iraniens?|russes?|chinois)"
            r"|cyber[\s-]?fanatiques?\s+pro[\s-]",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Malware",
        "re": re.compile(
            r"piratage\s+.{0,30}(revendiqu|hackers?|pirates?)"
            r"|pirates?\s+informatiques?\s+(arrêtés?|interpellés?|identifiés?)",
            re.IGNORECASE,
        ),
        "confidence": 80,
    },
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"cyberattaque|attaque\s+informatique|piratage\s+informatique"
            r"|cybercriminel|cybersécurité\s+.{0,20}(attaque|incident|alerte|menace)"
            r"|cyber\s*guerre|cyberguerre|piratage\s+de\s+données"
            r"|hackers?\s+.{0,20}recrutés?"
            # Italian catch-all
            r"|cyber\s+attacchi|attacchi?\s+informatici?"
            r"|più\s+colpiti?\s+al\s+mondo"
            # Portuguese catch-all
            r"|ataque\s+hacker|pode\s+acontecer\s+com\s+outras",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    # Japanese
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"サイバー攻撃|サイバーセキュリティ|不正アクセス|情報漏[洩えい]"
            r"|ランサムウェア|フィッシング|マルウェア|脆弱性",
        ),
        "confidence": 75,
    },
    # German
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"Cyberangriff|Cyberattacke|Hackerangriff|Datenleck"
            r"|Sicherheitslücke|Ransomware-Angriff|Phishing-Angriff",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    # Spanish
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"ciberataque|ataque\s+cibernético|hackeo|hackers?\s+.{0,20}(atac|invad|roban)"
            r"|brecha\s+de\s+(datos|seguridad)|ciberseguridad\s+.{0,20}(ataque|incidente|alerta)"
            r"|piratería\s+informática",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    # Portuguese
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"ataque\s+hacker|ciberataque|ataque\s+cibernético"
            r"|hackers?\s+.{0,20}(atacam|invadem|roubam)"
            r"|vazamento\s+de\s+dados|brecha\s+de\s+segurança",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    # Italian
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"cyber\s+attacch|attacco\s+informatico|attacco\s+hacker"
            r"|violazione\s+dei\s+dati|sicurezza\s+informatica\s+.{0,20}(attacco|incidente)",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    # English catch-all: generic cyber attack / incident / hack articles
    # that don't match any specific category above
    {
        "category": "General Cyber Threat",
        "re": re.compile(
            r"cyber\s*attack|cyber\s*incident|cybersecurity\s+incident"
            r"|cyber[\s-]*intrusion|cyber[\s-]*offensive"
            r"|\bhacked\b|\bhack\b(?!\s*(day|night|life|around|together))"
            r"|hacking\s+(crisis|campaign|group|operation)"
            r"|security\s+breach|security\s+incident"
            r"|systems?\s+taken\s+offline|takes?\s+systems?\s+offline"
            r"|critical\s+flaw|critical\s+vulnerability"
            r"|critical\s+.{0,20}(auth\s+bypass|gives?\s+.{0,10}access)"
            r"|under\s+attack|hit\s+by\s+(a\s+)?(cyber|hack|attack)"
            r"|impacted\s+by\s+(cyber|hack|attack)"
            r"|confirms?\s+(cyber|hack|breach|incident|attack)"
            r"|investigat\w+\s+(cyber|hack|breach|incident)"
            r"|reports?\s+(cyber|hack|breach|incident)"
            r"|\bmajor\s+(cyber\s+)?incident\b"
            r"|compromised\s+(system|network|server|data|account)"
            r"|unauthorized\s+access"
            r"|cyber\s*war(fare)?\b"
            r"|weaponi[sz]ing\s+.{0,20}(cyber|AI|ChatGPT)"
            r"|token\s+compromise|credential\s+siphon"
            r"|allegedly\s+(claims?|leak|dump)"
            r"|hackers?\s+claim|claim\s+(theft|data)"
            r"|patient\s+data\s+.{0,20}(disclosed|exposed|breach)"
            r"|medical\s+records?\s+.{0,10}(breach|hack|access)"
            r"|data\s+for\s+\$\d"
            r"|threaten\s+(public\s+)?leak"
            r"|records?\s+at\s+risk"
            r"|flexes?\s+.{0,10}cyber\s+chops"
            r"|hackers?\s+(accessed|stole|obtained|exfiltrated)\s+.{0,20}(record|data|patient|customer)"
            r"|breach\s+(claimed|leaks?|exposes?|reveals?)"
            r"|claimed\s+by\s+\w+\s*\w*\s*\|"
            r"|source\s+code\s+breach"
            r"|credentials?\s+exposed"
            r"|flaw\s+(now\s+)?exploit"
            r"|under\s+active\s+attack"
            r"|exploits?\s+attack"
            r"|goes?\s+to\s+war\b"
            r"|attacks?\s+millions?\s+of"
            r"|costs?\s+.{0,20}£?\$?\d+[MBmb]\s+in\s+(downtime|damage|loss)"
            r"|cyber[\s-]*attacks?\s+cost"
            r"|lays?\s+off\s+.{0,10}employees.{0,20}(AI|cyber)"
            r"|reports?\s+.{0,15}breach"
            r"|confirms?\s+.{0,20}breach"
            r"|no\s+evidence\s+hackers?\s+accessed"
            r"|patch\s+now.{0,5}(chrome|firefox|windows|iOS|android)"
            r"|under\s+cyber\s+fire"
            r"|cyber\s+resilience|cyber\s+threat|threat\s+landscape"
            r"|malicious\s+(actors?|activity|campaign|code|package)"
            r"|threat\s+intelligence\s+(report|brief|update|round)"
            r"|(flags?|warns?|alerts?)\s+.{0,20}(cyber|hack|breach|threat|vuln)"
            r"|faces?\s+cyber\s+incident"
            r"|recover\w*\s+from\s+(cyber|hack|attack|breach)"
            r"|cyber\s+breach|cyber\s+espionage"
            r"|suffers?\s+(attack|hack|breach|intrusion)"
            r"|disrupted\s+by\s+(cyber|hack|attack)"
            r"|targeted\s+by\s+(cyber|hack|threat|actor)"
            r"|IOCs?\s+detected"
            r"|new\s+victim\s+published",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
]

# Noise patterns — match articles that pass the cyber keyword check
# but are NOT actual threat intelligence (jobs, funding, PR, etc.)
_NOISE_PATTERNS = [
    # Job listings / career content
    re.compile(
        r"cybersecurity\s+jobs?\s+(available|listing|opening|posted)"
        r"|jobs?\s+available\s+right\s+now"
        r"|clearance\s*jobs\s+(available|listing|opening|posted)"
        r"|cybersecurity\s+(career|workforce|talent)\s+(path|shortage|gap|pipeline|crisis)"
        r"|(salary|pay|compensation)\s+(guide|survey|report|trends?)"
        r"|skills?\s+(gap|shortage)\s+(report|survey|crisis)"
        r"|cybersecurity\s+hiring\s+(trends?|challenges?|crisis)",
        re.IGNORECASE,
    ),
    # Workforce diversity opinion pieces (not threat intel)
    re.compile(
        r"(women|gender|diversity|inclusion)\s+(in|say|are\s+shaping|shaping)\s+.{0,20}(cyber|security|infosec)"
        r"|welcoming\s+career"
        r"|turning\s+expertise\s+into\s+opportunity",
        re.IGNORECASE,
    ),
    # Vendor funding rounds
    re.compile(
        r"\b(raises?|lands?|secures?|closes?)\s+\$\d+[\d.]*\s*(million|m\b|billion|b\b)"
        r"|series\s+[A-D]\s+(funding|round|raise)"
        r"|seed\s+round|funding\s+round",
        re.IGNORECASE,
    ),
    # Conference / event marketing
    re.compile(
        r"(register\s+now|join\s+us)\s+(for|at)\s+"
        r"|webinar\s+(guide|for\s+security\s+leaders)",
        re.IGNORECASE,
    ),
    # Celebrity / entertainment using 'cyber attack' loosely
    re.compile(
        r"(apologises?|apologizes?)\s+to\s+\w+\s+for\s+cyber"
        r"|mammootty|bollywood.*cyber",
        re.IGNORECASE,
    ),
    # M&A / business deals (not threat intel)
    re.compile(
        r"cybersecurity\s+M&A\s+roundup"
        r"|venture\s+investor.*cyber|dark\s+horse\s+for\s+venture"
        r"|cyber\s+insurance\s+premium",
        re.IGNORECASE,
    ),
    # Networking / career events (not threat intel)
    re.compile(
        r"networking\s+breakfast"
        r"|talent\s+under\s+one\s+roof"
        r"|expanding\s+the\s+pool\s+of\s+.*talent"
        r"|arts?\s+graduate\s+ended\s+up\s+managing\s+cyber",
        re.IGNORECASE,
    ),
    # Non-cyber social/political (matched cyber keywords loosely)
    re.compile(
        r"\bban\s+children\b.*social\s+media"
        r"|arrests?\s+\d+\s+people\s+for\s+sharing"
        r"|\bkids\b.*digital\s+safety\s+act",
        re.IGNORECASE,
    ),
    # Product announcements / roundups (not threat intel)
    re.compile(
        r"(infosec|cybersecurity|security)\s+products?\s+of\s+the\s+(week|month)"
        r"|new\s+(infosec|cybersecurity|security)\s+products?"
        r"|products?\s+(launch|announc|releas|unveil|introduc)"
        r"|top\s+\d+\s+(infosec|cybersecurity|security)\s+(tools?|products?|solutions?)"
        r"|vendor\s+spotlight|product\s+review\s+roundup",
        re.IGNORECASE,
    ),
    # Certification / training content (not threat intel)
    re.compile(
        r"(get|earn|obtain|achieve|pass)\s+(your\s+)?(cissp|cism|ceh|comptia|ccna|oscp|gcih|gsec|gpen|sans\s+course)"
        r"|(cissp|cism|ceh|oscp|security\+|cloud\+)\s+(certification|exam|prep|study|course|bootcamp|training)"
        r"|cybersecurity\s+(training|bootcamp|course|certification|degree|program)\s+(for|online|now)"
        r"|learn\s+(ethical\s+hacking|penetration\s+testing|cybersecurity)\s+(online|today|for\s+free)"
        r"|free\s+cybersecurity\s+(course|training|tutorial|resources?)"
        r"|certification\s+training\s+(to|for|program)"
        r"|provides?\s+cyber\s*security\s+certification\s+training"
        r"|training\s+gaps?\s+(impact|affect)\w*\s+.{0,20}cyber"
        r"|(adds?|unveils?)\s+.{0,20}cyber\s+security\s+course",
        re.IGNORECASE,
    ),
    # Generic cybersecurity advice / tips (not incident reporting)
    re.compile(
        r"\d+\s+(pro\s+)?(tips?|ways?|steps?|practices?|strategies?)\s+(to|for)\s+(protect|secure|stay|prevent|avoid|better)"
        r"|(top|best|essential)\s+\d+\s+(tips?|ways?|steps?|practices?|strategies?|tools?)\s+(to|for)\s+(protect|secure|stay|prevent|avoid)"
        r"|how\s+to\s+(protect|secure|stay\s+safe)\s+(your|against|from)\s+.{0,40}(cyber|hack|threat|attack|phish)"
        r"|(protect|secure)\s+your(self|business|company|organization)\s+(from|against)\s+(cyber|hack|ransomware|phishing)"
        r"|cybersecurity\s+awareness\s+(month|week|day|tips?|best\s+practices?)",
        re.IGNORECASE,
    ),
    # Crypto/NFT investment content falsely matching theft keywords
    re.compile(
        r"(buy|sell|invest(ing)?|trading|portfolio|hodl|bullish|bearish)\s+(bitcoin|ethereum|crypto|nft|defi|altcoin)"
        r"|(bitcoin|ethereum|crypto)\s+(price|rally|surge|dip|prediction|forecast|bull\s+run|bear\s+market)"
        r"|crypto\s+(market|exchange|wallet)\s+(update|news|analysis|review|report)\b(?!.*hack)(?!.*breach)(?!.*exploit)",
        re.IGNORECASE,
    ),
    # Awards / recognition (not threat intel)
    re.compile(
        r"wins?\s+(gold|silver|award|recognition)\s+at"
        r"|excellence\s+award|award[\s-]winning\s+(cyber|security)"
        r"|named\s+(leader|visionary|challenger)\s+in\s+(gartner|forrester|idc)",
        re.IGNORECASE,
    ),
    # Grants / government funding (not threat intel)
    re.compile(
        r"receive[sd]?\s+\$[\d,]+\s+(grant|funding)\s+.{0,30}(cyber|security)"
        r"|grant\s+to\s+(enhance|improve|strengthen)\s+cyber",
        re.IGNORECASE,
    ),
    # Legal hires / partner announcements
    re.compile(
        r"joins?\s+as\s+.{0,30}(partner|counsel|director|vp|head)\s+.{0,20}(cyber|data|privacy)"
        r"|expand\s+.{0,20}(cybersecurity|data|privacy)\s+practice",
        re.IGNORECASE,
    ),
    # Insurance / market commentary (not incidents)
    re.compile(
        r"cyber\s+insurance\s+(market|premium|rate|cost|trend|outlook)"
        r"|insurance\s+.*cyber\s+(risk|coverage|policy|protection)"
        r"|\bcyber\s+protection\s+in\b",
        re.IGNORECASE,
    ),
    # Acquisitions / business expansion (not threat intel)
    re.compile(
        r"(acquires?|acquisition)\s+.{0,40}(cyber|security)"
        r"|strengthen.{0,20}(cyber|security)\s+sector"
        r"|expand.{0,20}(cyber|security)\s+(capabilities|portfolio|offerings)",
        re.IGNORECASE,
    ),
    # Product/platform launches (not threat intel)
    re.compile(
        r"launches?\s+.{0,30}(autonomous|self.healing|AI.powered)\s+.{0,20}(agents?|platform|solution)"
        r"|launches?\s+.{0,30}(event|conference|summit)\s+(focused|dedicated)"
        r"|launches?\s+.{0,30}(cyber\s*security|security)\s+(club|program|initiative|academy)"
        r"|launches?\s+.{0,30}(new\s+)?(platform|solution|tool)\s+(to|for)\s+(protect|secure|transform|manage)"
        r"|unveils?\s+.{0,30}(platform|solution)\s+(powered|to\s+transform)",
        re.IGNORECASE,
    ),
    # Landscape/trend opinion pieces (not threat intel)
    re.compile(
        r"(reshape|reshaping|transform|shaping)\s+(the\s+)?(global\s+)?(cyber\s*security|security)\s+landscape"
        r"|state\s+of\s+(the\s+)?(cyber\s*security|security)\s+(market|industry|sector)"
        r"|(cyber\s*security|security)\s+spending\s+(trends?|forecast|outlook|in\s+\w+$)",
        re.IGNORECASE,
    ),
    # Government cyber strategy/policy (not incidents)
    re.compile(
        r"(govt|government)\s+(adopts?|announces?|unveils?)\s+.{0,30}(cyber|security)\s+(strategy|policy|plan)"
        r"|convene\s+.{0,20}(cyber|security)\s+conference",
        re.IGNORECASE,
    ),
    # Risk assessment commentary (not actual incidents)
    re.compile(
        r"(entities|organizations?|companies)\s+face\s+(heightened|increased|growing)\s+cyber\s+risk"
        r"|cyber\s+(risk|threat)\s+(related\s+to|from|amid)",
        re.IGNORECASE,
    ),
    # French noise — generic advice/prevention articles (not incidents)
    re.compile(
        r"cybersécurité\s+.{0,30}(prévenir|protéger|sensibilis|bonnes\s+pratiques|conseils)"
        r"|sensibilise\s+.{0,20}(organisations?|entreprises?|bonnes\s+pratiques)",
        re.IGNORECASE,
    ),
    # Leader/badge reports (vendor marketing)
    re.compile(
        r"(named|cites?d?)\s+.{0,40}leader\s+in\s+.{0,60}(evaluation|report)\b"
        r"|snags?\s+.{0,10}(leader\s+)?badges?\s+in\s+G2"
        r"|leader\s+in\s+.{0,30}(evaluation|report|platform)"
        r"|leader\s+in\s+(gartner|forrester|idc|independent\s+research)",
        re.IGNORECASE,
    ),
    # Certification achievements (vendor marketing, not incidents)
    re.compile(
        r"achieves?\s+.{0,30}(certification|certified|compliance|accreditation)"
        r"|achieves?\s+(level|tier)\s+\d\s+.{0,20}(certification|cmmc|hitrust)",
        re.IGNORECASE,
    ),
    # Cybersecurity training/upskilling (not incidents)
    re.compile(
        r"(train|upskill)\s+\d+[,.]?\d*\s*(cyber|security|specialist)"
        r"|smartest\s+career\s+move"
        r"|sets?\s+course\s+to\s+train"
        r"|enterprise[\s-]grade\s+.{0,20}training"
        r"|fully\s+managed\s+cybersecurity\s+solution\s+for",
        re.IGNORECASE,
    ),
    # Business/opinion/editorial about cybersecurity (not incidents)
    re.compile(
        r"(boards?|CEOs?|CFOs?|CISOs?)\s+(are\s+)?(falling\s+short|accountable|problem)\s+.{0,20}cyber"
        r"|cybersecurity\s+(is\s+increasingly|in\s+the\s+age\s+of|considerations?\s+\d{4}|gaps?\s+endanger)"
        r"|why\s+every\s+business\s+needs\s+to\s+.{0,20}cyber"
        r"|cybersecurity\s+(expert|pro)\s*(demonstrates?|says?|explains?)"
        r"|(steps?|ways?)\s+to\s+achieve\s+.{0,20}(resilience|compliance)"
        r"|free\s+to\s+attend\s+cyber|masterclass.{0,20}cyber"
        r"|shaping\s+the\s+next\s+generation"
        r"|insights?\s+from\s+RSAC"
        r"|growth\s+stocks?\s+to\s+buy"
        r"|cyber\s+security\s+lifeboat"
        r"|hottest\s+.{0,20}open.source\s+tools"
        r"|white\s+paper\s+for\s+.{0,30}(networks?|communications?)"
        r"|reducing\s+your\s+exposure\s+.{0,20}liability"
        r"|MSP\s+maturity"
        r"|art\s+as\s+a\s+mirror",
        re.IGNORECASE,
    ),
    # Investment/commitment in cybersecurity (not incidents)
    re.compile(
        r"(commits?|invest)\s+.{0,10}\$?\d+\s*(bln|billion|million|m\b).{0,20}(cyber|AI|infrastructure)"
        r"|to\s+invest\s+\$\d+.{0,30}cyber"
        r"|venture\s+capital.{0,20}cyber"
        r"|bought\s+by\s+(a\s+)?cyber\s+security\s+company"
        r"|strengthens?\s+(compliance|data\s+protection).{0,20}(appointment|practice)"
        r"|introduces?\s+.{0,30}(manager|tool)\s+for\s+.{0,20}compliance"
        r"|national\s+cyber\w*\s+coordination\s+council"
        r"|media\s+advisory.{0,30}(adapt|closing\s+the)",
        re.IGNORECASE,
    ),
    # Cybersecurity market/industry report noise
    re.compile(
        r"cybersecurity\s+.{0,20}(trust|priorities|AI\s+risks?)\s+(is\s+becoming|for\s+insurers)"
        r"|cybersecurity\s+in\s+(logistics|the\s+age)"
        r"|hits?\s+\d+[,.]?\d*\s+clients"
        r"|appoints?\s+.{0,30}(country\s+manager|director|head)"
        r"|predictive\s+cybersecurity\s+with"
        r"|introduces?\s+.{0,20}(requirements?|sustainability)"
        r"|publishes?\s+.{0,20}white\s+paper"
        r"|sweeps?\s+.{0,15}(major\s+)?awards?"
        r"|cybersecurity\s+-\s+\w+\s+News$",
        re.IGNORECASE,
    ),
    # More editorial/opinion noise
    re.compile(
        r"only\s+\d+%\s+of\s+organizations?\s+have"
        r"|cybersecurity\s+can\s+learn\s+from"
        r"|what\s+does\s+cyber\s+resilience\s+look\s+like"
        r"|doing\s+more\s+with\s+less\s+in"
        r"|information\s+sharing\s+of\s+cyber\s+threats?\s+vital"
        r"|top\s+\d+:?\s+(CISOs?|cyber\s+leaders?)\s+(in|of)"
        r"|playbook\s+for\s+.{0,20}(cost|reliable|effective)\s+cyber"
        r"|spotlight\s+cybersecurity\s+growth"
        r"|cybersecurity\s+stocks?\s+(fall|rise|drop|surge)"
        r"|key\s+.{0,20}takeaways?\s+from\s+(the\s+)?(NAIC|RSAC|RSA)"
        r"|industry\s+leaders?\s+warn.{0,20}cybersecurity"
        r"|AI\s+runs?\s+on\s+trust.{0,20}cyber"
        r"|simple\s+mistakes.{0,10}here.s\s+the\s+real\s+lesson"
        r"|hosting\s+.{0,10}cybersecurity\s+events?"
        r"|responding\s+to\s+a\s+cyber.attack\s+-\s+(KPMG|Deloitte|PwC|EY)"
        r"|cyber\s+warfare\s+101"
        r"|cybergames"
        r"|myriad\s+threats?\s+challenge"
        r"|best\s+ethical\s+hacking\s+(courses?|certifications?)"
        r"|cybersecurity\s+expert.{0,10}(presenters?|tackle\s+threats)"
        r"|signals?\s+new\s+era\s+of\s+AI\s+cyber"
        r"|\bnew\s+era\s+of\s+.{0,20}risk\s+and\s+investment"
        r"|cyber\s+risk\s+management\s+game"
        r"|fight\s+to\s+keep\s+.{0,20}safe\s+from\s+cyber"
        r"|government\s+needs\s+to\s+take\s+cyber"
        r"|venture\s+capital\s+leader\s+eyes"
        r"|liability\s+limitations\s+for\s+cyber"
        r"|foundation\s+of\s+intelligent\s+security"
        r"|strengthens?\s+(compliance|data\s+protection).{0,20}(appointment|practice)"
        r"|NCSC\s+Gold\s+Award"
        r"|prestigious\s+.{0,20}(award|certification)"
        r"|AI\s+security\s+into\s+the\s+heart\s+of.{0,20}certifications?"
        r"|cybersecurity\s+expert.{0,5}why\s+your\s+business"
        r"|announces?\s+(core\s+)?(AI\s+)?patent"
        r"|data\s+regulators?\s+support\s+loosening"
        r"|presents?\s+bill\s+to\s+reinforce\s+cyber"
        r"|mighty\s+mission\s+to\s+.{0,10}(cyber|resilient)"
        r"|harder\s+to\s+price\s+and\s+manage"
        r"|vulnerability\s+statistics?\s+\d{4}"
        r"|cybersecurity\s+-\s+\w+\s+(News|Sun)$"
        r"|becomes?\s+immune\s+to\s+(ransomware|malware|attack)"
        r"|kit\s+de\s+crise\s+.{0,20}(collectivités|entreprises)"
        r"|opération\s+.{0,20}(Cactus|sensibilis)"
        r"|résultats\s+de\s+l.opération",
        re.IGNORECASE,
    ),
    # Market/stock/forecast reports mentioning cyber
    re.compile(
        r"(market|stock)\s+(forecast|reaction|overview|outlook|analysis|size|report|growth)"
        r"|\bmarket\s+forecast\s+points?\s+higher"
        r"|driven\s+by\s+(regulatory\s+)?mandates?"
        r"|cybersecurity\s+stocks?\s+(after|amid|following)"
        r"|future\s+of\s+cyber\s*security\s+is\s+a\s+machine"
        r"|quietly\s+becoming\s+.{0,30}enforcement"
        r"|click,?\s+wait,?\s+repeat"
        r"|digital\s+trust\s+erodes"
        r"|tightens?\s+digital\s+control"
        r"|condition\s+de\s+la\s+souveraineté",
        re.IGNORECASE,
    ),
]

logger = logging.getLogger(__name__)

# Broad cybersecurity relevance check
_CYBER_KEYWORDS = re.compile(
    r"cyber|hack|breach|malware|ransomware|phishing|vulnerability|exploit"
    r"|ddos|botnet|trojan|apt\d|zero.day|cve-|security\s+incident"
    r"|data\s+leak|threat\s+actor|attack|infosec|cisa|ncsc"
    r"|patch\s+tuesday|critical\s+vuln|backdoor|credential"
    r"|authentication|encryption|firewall|endpoint\s+security"
    r"|soc\s+|siem|penetration\s+test|bug\s+bounty|dark\s+web"
    r"|rootkit|spyware|keylogger|wiper|cryptojack"
    # French
    r"|cyberattaque|piratage|rançongiciel|fuite\s+de\s+données"
    # Japanese
    r"|サイバー攻撃|不正アクセス|情報漏|ランサムウェア|フィッシング|マルウェア|脆弱性"
    # German
    r"|Cyberangriff|Cyberattacke|Hackerangriff|Datenleck|Sicherheitslücke"
    # Spanish
    r"|ciberataque|ataque\s+cibernético|hackeo|piratería\s+informática"
    # Portuguese
    r"|ataque\s+hacker|vazamento\s+de\s+dados"
    # Italian
    r"|cyber\s+attacch|attacco\s+informatico|attacco\s+hacker",
    re.IGNORECASE,
)


# Categories that indicate a specific actor/context — these should win over
# generic technique categories (Malware, Zero-Day) when both match.
_CONTEXT_PRIORITY = {
    "Nation-State Attack": 15,
    "Supply Chain Attack": 12,
    "Critical Infrastructure Attack": 12,
    "Cyber Espionage": 10,
    "Ransomware": 8,
    "Data Breach": 5,
    "Patch/Security Update": 5,
    "Phishing": 3,
}


# Compound-event rules: when two categories co-occur, the "outcome" (what
# happened) should win over the "method" (how it happened) IF the outcome
# keyword appears explicitly in the title.
_COMPOUND_OVERRIDES = [
    # "data breach" + ransomware → Data Breach (breach is the outcome)
    {"if_both": ("Ransomware", "Data Breach"),
     "title_re": re.compile(r"data\s+breach|breached|data\s+leak|records\s+(stolen|exposed)", re.I),
     "winner": "Data Breach"},
    # phishing + data breach → Phishing (phishing is the specific technique)
    {"if_both": ("Data Breach", "Phishing"),
     "title_re": re.compile(r"phishing|spearphish|credential\s+harvest|\bbec\b|business\s+email", re.I),
     "winner": "Phishing"},
    # supply chain + zero-day → Zero-Day (more specific)
    {"if_both": ("Supply Chain Attack", "Zero-Day Exploit"),
     "title_re": re.compile(r"zero.day|0day|actively\s+exploited", re.I),
     "winner": "Zero-Day Exploit"},
    # supply chain + phishing → Phishing (when phishing is the method described)
    {"if_both": ("Supply Chain Attack", "Phishing"),
     "title_re": re.compile(r"phishing|credential\s+harvest|fake\s+login", re.I),
     "winner": "Phishing"},
    # ransomware + nation-state → Nation-State Attack (attribution matters more)
    {"if_both": ("Ransomware", "Nation-State Attack"),
     "title_re": re.compile(r"nation.state|state.sponsored|apt\d|lazarus|typhoon|sandworm|bear|kitten", re.I),
     "winner": "Nation-State Attack"},
    # nation-state + data breach → Data Breach (when breach is the headline)
    {"if_both": ("Nation-State Attack", "Data Breach"),
     "title_re": re.compile(r"data\s+breach|breached|records\s+(stolen|exposed)|data\s+leak", re.I),
     "winner": "Data Breach"},
    # malware + phishing → Phishing (when phishing is the delivery vector described)
    {"if_both": ("Malware", "Phishing"),
     "title_re": re.compile(r"phishing|spearphish|credential\s+harvest|\bbec\b|fake\s+invoice", re.I),
     "winner": "Phishing"},
    # zero-day + ransomware → Ransomware (when ransomware is the payload)
    {"if_both": ("Zero-Day Exploit", "Ransomware"),
     "title_re": re.compile(r"ransomware|ransom\s+demand|lockbit|blackcat|cl0p|akira", re.I),
     "winner": "Ransomware"},
    # ransomware + phishing → Phishing (when phishing is the method in the title)
    {"if_both": ("Ransomware", "Phishing"),
     "title_re": re.compile(r"phishing|credential\s+harvest", re.I),
     "winner": "Phishing"},
    # nation-state + zero-day → Zero-Day (when zero-day is the vulnerability described)
    {"if_both": ("Nation-State Attack", "Zero-Day Exploit"),
     "title_re": re.compile(r"zero.day|0day|vulnerability\s+exploit", re.I),
     "winner": "Zero-Day Exploit"},
]


def _resolve_compound_events(matches, matched_cats, title):
    """Override scoring when two categories co-occur and title disambiguates."""
    for rule in _COMPOUND_OVERRIDES:
        cat_a, cat_b = rule["if_both"]
        if cat_a in matched_cats and cat_b in matched_cats:
            if rule["title_re"].search(title):
                winner = rule["winner"]
                # Give the winner a massive score boost to ensure it wins
                return [
                    (cat, conf, score + 50) if cat == winner else (cat, conf, score)
                    for cat, conf, score in matches
                ]
    return matches


def classify_article(title, content=None, source_language="en"):
    """Classify an article using keyword patterns with multi-match scoring.

    All matching rules are collected. The winner is chosen by:
    1. Context-priority bonus (actor/campaign > technique)
    2. Base confidence from the rule

    Returns same dict structure as ai_engine.analyze_article for compatibility.
    """
    cache_key = _compute_hash(title + (content or ""))

    cached = get_cached_result(cache_key)
    if cached is not None:
        cached["_cached"] = True
        return cached

    text = title + " " + (content or "")

    # Collect ALL matching rules (not just the first)
    # Title-match bonus: +10 if the rule matches the title directly (not just body)
    matches = []
    for rule in _RULES:
        if rule["re"].search(text):
            priority_bonus = _CONTEXT_PRIORITY.get(rule["category"], 0)
            title_bonus = 10 if rule["re"].search(title) else 0
            score = rule["confidence"] + priority_bonus + title_bonus
            matches.append((rule["category"], rule["confidence"], score))

    # Compound-event resolver: when two categories co-occur, the "outcome"
    # category wins over the "method" if the outcome appears in the title.
    matched_cats = {m[0] for m in matches}
    if matches:
        matches = _resolve_compound_events(matches, matched_cats, title)

    if matches:
        # Pick the highest-scoring match
        best = max(matches, key=lambda m: m[2])
        category = best[0]
        confidence = best[1]
        rule_matched = True
    else:
        category = "General Cyber Threat"
        confidence = 60
        rule_matched = False

    # Check if cybersecurity-related (broad keywords OR specific rule match)
    is_cyber = rule_matched or bool(_CYBER_KEYWORDS.search(text))

    if not is_cyber:
        result = {
            "is_cyber_attack": False,
            "category": "General Cyber Threat",
            "confidence": 0,
            "translated_title": title,
            "summary": "",
        }
        cache_result(cache_key, result)
        return result

    # Filter out noise — passes cyber check but is not threat intel
    for noise_re in _NOISE_PATTERNS:
        if noise_re.search(text):
            logger.debug("Noise filtered: %s", title[:80])
            result = {
                "is_cyber_attack": False,
                "category": "Noise",
                "confidence": 0,
                "translated_title": title,
                "summary": "",
            }
            cache_result(cache_key, result)
            return result

    # Use RSS summary as the article summary (free, no AI needed)
    summary = ""
    if content:
        # Take first 3 sentences from content as summary
        sentences = re.split(r'(?<=[.!?])\s+', content.strip())
        summary = " ".join(sentences[:3])
        if len(summary) > 500:
            summary = summary[:497] + "..."

    result = {
        "is_cyber_attack": True,
        "category": category,
        "confidence": confidence,
        "translated_title": title,
        "summary": summary,
    }

    cache_result(cache_key, result)
    return result


def _rules_version():
    """Hash of all rule/noise/compound patterns for cache invalidation."""
    parts = [r["re"].pattern + r["category"] for r in _RULES]
    parts.extend(p.pattern for p in _NOISE_PATTERNS)
    for c in _COMPOUND_OVERRIDES:
        parts.append(c["title_re"].pattern + c["winner"])
    return hashlib.sha256("".join(parts).encode()).hexdigest()[:12]


_RULES_VERSION = _rules_version()


def _compute_hash(text):
    return hashlib.sha256(
        (_RULES_VERSION + text[:MAX_CONTENT_CHARS]).encode()
    ).hexdigest()
