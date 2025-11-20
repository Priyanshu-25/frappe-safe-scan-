import ast
import sys
import json
from pathlib import Path

class EvalExecVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        func = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)

        if func in ("eval", "exec"):
            self.issues.append((node.lineno, f"Use of dangerous call: {func}()"))

        if func in ("Popen", "call", "run") and isinstance(node.func, ast.Attribute):
            self.issues.append((node.lineno, f"Potential unsafe subprocess usage: {func}"))

        self.generic_visit(node)

class SQLConcatVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Add):
            if isinstance(node.left, ast.Constant) or isinstance(node.right, ast.Constant):
                if isinstance(node.left.value, str) or isinstance(node.right.value, str):
                    self.issues.append((node.lineno,
                        "Possible SQL injection risk due to string concatenation"))
        self.generic_visit(node)

class HardcodedSecretVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                if any(k in target.id.lower() for k in ("secret","password","key","token")):
                    if isinstance(node.value, ast.Constant):
                        self.issues.append((node.lineno,
                            f"Hardcoded secret in variable '{target.id}'"))
        self.generic_visit(node)

def scan_file(path: Path):
    issues = []
    try:
        tree = ast.parse(path.read_text())
        visitors = [EvalExecVisitor(), SQLConcatVisitor(), HardcodedSecretVisitor()]
        for v in visitors:
            v.visit(tree)
            issues.extend(v.issues)
        return issues
    except Exception as e:
        return [(-1, f"Parse error: {e}")]

def scan_directory(dirpath):
    results = {}
    for py in Path(dirpath).rglob("*.py"):
        issues = scan_file(py)
        if issues:
            results[str(py)] = [{"line": ln, "message": msg} for ln, msg in issues]
    return results

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python frappe_safe_scan.py <path>")
        sys.exit(1)

    path = sys.argv[1]
    results = scan_directory(path)
    print(json.dumps(results, indent=2))
