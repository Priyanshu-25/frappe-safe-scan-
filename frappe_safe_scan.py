# frappe_safe_scan.py
import ast
import sys
import json
from pathlib import Path

CHECKS = []

class EvalExecVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        try:
            func_name = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
            if func_name in ('eval', 'exec'):
                self.issues.append((node.lineno, f"Use of {func_name}()"))
            # check for subprocess calls
            if func_name in ('Popen','call','run') and isinstance(node.func, ast.Attribute):
                self.issues.append((node.lineno, f"Possible subprocess call: {ast.unparse(node.func)}"))
        except Exception:
            pass
        self.generic_visit(node)

class SQLConcatVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_BinOp(self, node):
        # detect string concatenation used in assignments or calls (very heuristic)
        if isinstance(node.op, ast.Add):
            if isinstance(node.left, (ast.Constant, ast.Str)) or isinstance(node.right, (ast.Constant, ast.Str)):
                self.issues.append((node.lineno, "String concatenation — check for SQL injection risks"))
        self.generic_visit(node)

class HardcodedSecretVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and any(k in target.id.lower() for k in ("secret","password","token","key")):
                if isinstance(node.value, (ast.Constant, ast.Str)):
                    self.issues.append((node.lineno, f"Hardcoded secret in variable '{target.id}'"))
        self.generic_visit(node)

def scan_file(path: Path):
    try:
        src = path.read_text()
        tree = ast.parse(src)
        visitors = [EvalExecVisitor(), SQLConcatVisitor(), HardcodedSecretVisitor()]
        issues = []
        for v in visitors:
            v.visit(tree)
            issues.extend(v.issues)
        return issues
    except Exception as e:
        return [(-1, f"Parse error: {e}")]

def scan_dir(dirpath):
    results = {}
    for py in Path(dirpath).rglob("*.py"):
        issues = scan_file(py)
        if issues:
            results[str(py)] = [{"line": ln, "msg": msg} for ln,msg in issues]
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python frappe_safe_scan.py <path>")
        sys.exit(1)
    path = sys.argv[1]
    res = scan_dir(path)
    print(json.dumps(res, indent=2))
