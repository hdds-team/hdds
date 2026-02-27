#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com


################################################################################
# HDDS Code Quality Scan
#
# Full codebase scan for stubs, TODOs, FIXMEs, etc.
# (Unlike pre-commit hook which scans only staged files)
#
# Usage:
#  ./tools/git-hooks/scan-all.sh                    # Scan all prod code
#  ./tools/git-hooks/scan-all.sh --fix              # Show fix suggestions
#  ./tools/git-hooks/scan-all.sh --report           # JSON report
#  ./tools/git-hooks/scan-all.sh --strict           # Fail on warnings
################################################################################

set -u

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GIT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
readonly PROD_SRC="${GIT_ROOT}/crates/hdds/src"

# Flags (must init before parse_args due to set -u)
FIX_SUGGESTIONS=1
STRICT=0
REPORT=0
VERBOSE=0

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
GRAY='\033[0;90m'
NC='\033[0m'

# Counters
ERRORS=0
WARNINGS=0

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --strict) STRICT=1 ;;
            --report) REPORT=1 ;;
            --verbose) VERBOSE=1 ;;
            --fix|--suggestions) FIX_SUGGESTIONS=1 ;;
            --no-fix) FIX_SUGGESTIONS=0 ;;
            *) echo "Unknown flag: $1"; exit 1 ;;
        esac
        shift
    done
}

error() {
    echo -e "${RED}[X] $*${NC}" >&2
    ((ERRORS++))
}

warning() {
    echo -e "${YELLOW}[!]  $*${NC}"
    ((WARNINGS++))
}

info() {
    echo -e "${GREEN}[i]  $*${NC}"
}

scan_file() {
    local file="$1"
    local line_num=0
    local file_errors=0
    local file_warnings=0

    [[ ! -f "$file" ]] && return
    
    # Header for verbose
    if [[ $VERBOSE -eq 1 ]]; then
        echo -e "${BLUE}📄 $file${NC}"
    fi

    # Line-by-line scan
    while IFS= read -r line; do
        ((line_num++))
        
        # ERROR: Bare macros
        if [[ "$line" =~ todo!\(|unimplemented!\( ]]; then
            error "$file:$line_num -- Bare macro: $line"
            ((file_errors++))
        fi
        
        # ERROR: Empty stubs
        if [[ "$line" =~ ^[[:space:]]*pub[[:space:]]+fn[[:space:]]+[a-z_]+\(\)[[:space:]]*\{[[:space:]]*\} ]]; then
            error "$file:$line_num -- Empty stub: $line"
            ((file_errors++))
        fi
        
        # ERROR: FIXME
        if [[ "$line" =~ //[[:space:]]*FIXME ]]; then
            error "$file:$line_num -- FIXME (use TODO(v2.0+)): $line"
            ((file_errors++))
        fi
        
        # WARNING: Bare TODO
        if [[ "$line" =~ //[[:space:]]*TODO && ! "$line" =~ TODO\((v2\.|Phase|spec|unavoidable) ]]; then
            warning "$file:$line_num -- TODO without version: $line"
            ((file_warnings++))
        fi
        
        # WARNING: HACK without justification
        if [[ "$line" =~ //[[:space:]]*HACK && ! "$line" =~ HACK\((unavoidable|spec)\) ]]; then
            warning "$file:$line_num -- HACK without justification: $line"
            ((file_warnings++))
        fi
        
        # WARNING: XXX marker
        if [[ "$line" =~ //[[:space:]]*XXX ]]; then
            warning "$file:$line_num -- Vague XXX (use TODO): $line"
            ((file_warnings++))
        fi
        
    done < "$file"
    
    if [[ $file_errors -gt 0 || $file_warnings -gt 0 ]]; then
        echo -e "  ${RED}Errors:${NC} $file_errors, ${YELLOW}Warnings:${NC} $file_warnings"
    fi
}

scan_prod() {
    if [[ ! -d "$PROD_SRC" ]]; then
        echo "[X] Production source not found: $PROD_SRC"
        exit 1
    fi
    
    info "Scanning $PROD_SRC for violations..."
    echo ""
    
    find "$PROD_SRC" -type f -name "*.rs" | while read -r file; do
        scan_file "$file"
    done
}

print_summary() {
    echo ""
    echo -e "${BLUE}-----------------------------------------------------${NC}"
    echo -e "[i] Summary: ${RED}$ERRORS errors${NC}, ${YELLOW}$WARNINGS warnings${NC}"
    echo -e "${BLUE}-----------------------------------------------------${NC}"
    
    if [[ $ERRORS -eq 0 ]]; then
        echo -e "${GREEN}[OK] No critical errors found!${NC}"
    fi
    
    if [[ $ERRORS -gt 0 || ($WARNINGS -gt 0 && $STRICT -eq 1) ]]; then
        return 1
    fi
    
    return 0
}

print_suggestions() {
    if [[ $FIX_SUGGESTIONS -eq 0 ]]; then
        return
    fi
    
    echo ""
    echo -e "${BLUE}💡 Fix Suggestions:${NC}"
    echo ""
    echo "1. Bare macros (todo!/unimplemented!)"
    echo "   -> Remove or implement the functionality"
    echo "   -> If deferring: add // TODO(v2.0+): reason"
    echo ""
    echo "2. Empty stubs (pub fn name() { })"
    echo "   -> Implement or add // TODO(v2.0+): reason"
    echo "   -> Add #[allow(dead_code)] if truly unused"
    echo ""
    echo "3. FIXME markers"
    echo "   -> Convert to // TODO(v2.0+): reason"
    echo "   -> FIXME is discouraged; TODOs are actionable"
    echo ""
    echo "4. Bare TODOs (no version/phase)"
    echo "   -> Add version: // TODO(v2.0+): reason"
    echo "   -> Or phase: // TODO(Phase T3): reason"
    echo ""
    echo "5. HACK without justification"
    echo "   -> Either: // HACK(unavoidable): why this approach"
    echo "   -> Or: refactor and remove HACK"
    echo ""
    echo "6. XXX markers"
    echo "   -> Replace with specific TODO, FIXME, or NOTE"
    echo ""
}

print_whitelist_guide() {
    echo ""
    echo -e "${GRAY}-- Whitelisted Patterns --${NC}"
    echo "[OK] // TODO(v2.0+): reason"
    echo "[OK] // TODO(Phase N): reason"
    echo "[OK] // TODO(spec): reason (RTPS/XTypes spec pending)"
    echo "[OK] // NOTE: historical context"
    echo "[OK] // HACK(unavoidable): why"
    echo "[OK] // HACK(spec): spec limitation"
    echo "[OK] #[allow(dead_code)] // reason"
    echo ""
}

main() {
    parse_args "$@"
    
    echo -e "${BLUE}+====================================================+${NC}"
    echo -e "${BLUE}|         HDDS Code Quality Scanner (Full Scan)      |${NC}"
    echo -e "${BLUE}+====================================================+${NC}"
    echo ""
    
    scan_prod
    
    print_summary || EXIT_CODE=$?
    print_suggestions
    print_whitelist_guide
    
    return ${EXIT_CODE:-0}
}

main "$@"

