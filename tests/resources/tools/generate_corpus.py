from pathlib import Path
import json

ROOT = Path("tests/resources/dir/corpus/projects")
ROOT.mkdir(parents=True, exist_ok=True)

projects = [
    {
        "name": "py_vuln_small",
        "vulnerable": True,
        "language": "python",
        "files": {
            "app.py": "API_KEY='AKIAJX7LKQHMBQWRFP2A'\nimport requests\nrequests.get('https://api.local', headers={'X': API_KEY})\n",
        },
    },
    {
        "name": "py_clean_small",
        "vulnerable": False,
        "language": "python",
        "files": {"app.py": "API_KEY='example_key'\nprint('ok')\n"},
    },
    {
        "name": "py_vuln_nested",
        "vulnerable": True,
        "language": "python",
        "files": {
            "src/core/auth.py": "TOKEN='ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'\nimport logging\nlogging.info(TOKEN)\n",
        },
    },
    {
        "name": "py_clean_nested",
        "vulnerable": False,
        "language": "python",
        "files": {"src/core/auth.py": "TOKEN='dummy_token'\ndef run():\n    return 'ok'\n"},
    },
    {
        "name": "js_vuln_small",
        "vulnerable": True,
        "language": "javascript",
        "files": {
            "index.js": "const apiKey='AKIAJX7LKQHMBQWRFP2A';\nconsole.log(apiKey);\n",
        },
    },
    {
        "name": "js_clean_small",
        "vulnerable": False,
        "language": "javascript",
        "files": {"index.js": "const apiKey='example_test_key';\nconsole.log('safe');\n"},
    },
    {
        "name": "ts_vuln_nested",
        "vulnerable": True,
        "language": "typescript",
        "files": {
            "src/services/client.ts": "const token='ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW';\nconsole.log(token);\n",
        },
    },
    {
        "name": "ts_clean_nested",
        "vulnerable": False,
        "language": "typescript",
        "files": {"src/services/client.ts": "const token='placeholder_token';\nexport {};\n"},
    },
    {
        "name": "java_vuln_small",
        "vulnerable": True,
        "language": "java",
        "files": {
            "src/Main.java": 'class Main { public static void main(String[] a){ String p="AKIAJX7LKQHMBQWRFP2A"; System.out.println(p);} }\n'
        },
    },
    {
        "name": "java_clean_small",
        "vulnerable": False,
        "language": "java",
        "files": {
            "src/Main.java": 'class Main { public static void main(String[] a){ String p="example_password"; System.out.println(p);} }\n'
        },
    },
    {
        "name": "go_vuln_small",
        "vulnerable": True,
        "language": "go",
        "files": {
            "main.go": 'package main\nimport "fmt"\nfunc main(){fmt.Println("sk_live_abcdefghijklmnopqrstuvwx")}\n',
        },
    },
    {
        "name": "go_clean_small",
        "vulnerable": False,
        "language": "go",
        "files": {
            "main.go": 'package main\nimport "fmt"\nfunc main(){fmt.Println("example_token")}\n',
        },
    },
    {
        "name": "mixed_vuln_large",
        "vulnerable": True,
        "language": "mixed",
        "files": {
            "backend/config/.env": "DB_PASSWORD='UltraSecret_456!'\n",
            "frontend/src/config.ts": "export const auth='Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb';\n",
            "ops/infra.yaml": "redis: redis://admin:pass123@10.0.0.5:6379\n",
        },
    },
    {
        "name": "mixed_clean_large",
        "vulnerable": False,
        "language": "mixed",
        "files": {
            "backend/config/.env": "DB_PASSWORD='example_password'\n",
            "frontend/src/config.ts": "export const auth='Bearer placeholder';\n",
            "ops/infra.yaml": "redis: redis://localhost:6379\n",
        },
    },
    {
        "name": "php_vuln_nested",
        "vulnerable": True,
        "language": "php",
        "files": {"app/config/db.php": "<?php $pwd='SuperSecret123!'; echo $pwd;"},
    },
    {
        "name": "php_clean_nested",
        "vulnerable": False,
        "language": "php",
        "files": {"app/config/db.php": "<?php $pwd='example'; echo 'ok';"},
    },
    {
        "name": "csharp_vuln",
        "vulnerable": True,
        "language": "csharp",
        "files": {
            "Program.cs": 'using System; class P { static void Main(){ Console.WriteLine("AKIAJX7LKQHMBQWRFP2A"); } }',
        },
    },
    {
        "name": "csharp_clean",
        "vulnerable": False,
        "language": "csharp",
        "files": {
            "Program.cs": 'using System; class P { static void Main(){ Console.WriteLine("hello"); } }',
        },
    },
    {
        "name": "ruby_vuln",
        "vulnerable": True,
        "language": "ruby",
        "files": {
            "app.rb": "token = 'AKIAJX7LKQHMBQWRFP2A'\nputs token\n",
        },
    },
    {
        "name": "ruby_clean",
        "vulnerable": False,
        "language": "ruby",
        "files": {"app.rb": "token = 'example'\nputs token\n"},
    },
    {
        "name": "rust_clean_nested",
        "vulnerable": False,
        "language": "rust",
        "files": {"src/main.rs": 'fn main(){println!("safe");}\n'},
    },
    {
        "name": "rust_vuln_nested",
        "vulnerable": True,
        "language": "rust",
        "files": {"src/main.rs": 'fn main(){println!("AKIAJX7LKQHMBQWRFP2A");}\n'},
    },
]

for project in projects:
    base = ROOT / project["name"]
    for rel, content in project["files"].items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

manifest = [
    {"name": p["name"], "vulnerable": p["vulnerable"], "language": p["language"]}
    for p in projects
]
Path("tests/resources/dir/corpus/manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(f"created:{len(projects)}")
