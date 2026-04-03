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
            r"|million\s+records|account.*compromis",
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
            r"|buffer\s+overflow|authentication\s+bypass",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Patch/Security Update",
        "re": re.compile(
            r"patch\s+tuesday|security\s+patch|security\s+update"
            r"|hotfix|firmware\s+update|emergency\s+patch|out-of-band\s+patch"
            r"|security\s+advisory|critical\s+update",
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
            r"|cybercriminel|cybersécurité\s+.{0,20}(attaque|incident|alerte|menace)",
            re.IGNORECASE,
        ),
        "confidence": 72,
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
        r"|free\s+cybersecurity\s+(course|training|tutorial|resources?)",
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
        r"|launches?\s+.{0,30}(cyber\s*security|security)\s+(club|program|initiative|academy)",
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
    matches = []
    for rule in _RULES:
        if rule["re"].search(text):
            priority_bonus = _CONTEXT_PRIORITY.get(rule["category"], 0)
            score = rule["confidence"] + priority_bonus
            matches.append((rule["category"], rule["confidence"], score))

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
    """Hash of all rule patterns + noise patterns for cache invalidation."""
    parts = [r["re"].pattern + r["category"] for r in _RULES]
    parts.extend(p.pattern for p in _NOISE_PATTERNS)
    return hashlib.sha256("".join(parts).encode()).hexdigest()[:12]


_RULES_VERSION = _rules_version()


def _compute_hash(text):
    return hashlib.sha256(
        (_RULES_VERSION + text[:MAX_CONTENT_CHARS]).encode()
    ).hexdigest()
