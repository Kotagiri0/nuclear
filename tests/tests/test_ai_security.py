from __future__ import annotations

from scanner.ai.security import _parse_model_output


class TestAISecurityParsing:
    def test_safe_ru_returns_empty(self):
        assert _parse_model_output("[БЕЗОПАСНО]") == []
        assert _parse_model_output("БЕЗОПАСНО") == []

    def test_safe_en_returns_empty(self):
        assert _parse_model_output("[SAFE]") == []
        assert _parse_model_output("SAFE") == []

    def test_parses_ru_levels_with_line_numbers(self):
        out = _parse_model_output(
            "\n".join(
                [
                    "[КРИТИЧЕСКАЯ] - L3: os.system('rm -rf /')",
                    "[ВЫСОКАЯ] - L10: eval(user_input)",
                    "[СРЕДНЯЯ] - L2: subprocess.run(cmd, shell=True)",
                    "[НИЗКАЯ] - L1: print('debug')",
                ]
            )
        )
        assert out == [
            ("CRITICAL", 3, "os.system('rm -rf /')"),
            ("HIGH", 10, "eval(user_input)"),
            ("MEDIUM", 2, "subprocess.run(cmd, shell=True)"),
            ("LOW", 1, "print('debug')"),
        ]

    def test_ignores_garbage_lines(self):
        out = _parse_model_output(
            "\n".join(
                [
                    "some explanation (should be ignored)",
                    "[ВЫСОКАЯ] - L2: eval(x)",
                    "",
                    " - not matching",
                ]
            )
        )
        assert out == [("HIGH", 2, "eval(x)")]

    def test_parses_bracketless_format(self):
        out = _parse_model_output(
            "\n".join(
                [
                    "КРИТИЧЕСКАЯ - L4: os.system(\"echo \" + user_input)",
                    "ВЫСОКАЯ - L1: admin_pass = \"admin123\"",
                ]
            )
        )
        assert out == [
            ("CRITICAL", 4, "os.system(\"echo \" + user_input)"),
            ("HIGH", 1, "admin_pass = \"admin123\""),
        ]

