//////////////////////////////////////////
// SQL Injection Detection Rule
// Target: SQL keywords and operations, SQL tautologies and bypasses, Database-specific functions
//////////////////////////////////////////

rule sql_injection{

    meta:
        author = "Cisco"
        description = "Detects SQL injection attack patterns including keywords, tautologies, and database functions"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:

        // SQL injection tautologies and bypasses - focus on actual injection payloads
        $injection_tautologies = /(\bOR\s+['"]?1['"]?\s*=\s*['"]?1['"]?\s*(--|#|\/\*|;))/i

        // Destructive SQL injections
        $destructive_injections = /(';\s*DROP\s+TABLE|";\s*DROP\s+TABLE)/i

        // Union-based SQL injection
        $union_based_attacks = /(UNION\s+(ALL\s+)?SELECT|'\s*UNION\s+SELECT|"\s*UNION\s+SELECT)/i

        // Time-based blind injection techniques (SQL context only)
        $time_based_injections = /\b(SLEEP|WAITFOR\s+DELAY|BENCHMARK|pg_sleep)\s*\(/i

        // Exclude Python sleep functions (not SQL injection)
        $python_sleep = /(time\.sleep|asyncio\.sleep|threading\.[A-Za-z]*\.sleep)\s*\(/

        // Error-based injection methods
        $error_based_techniques = /\b(EXTRACTVALUE|UPDATEXML|EXP\(~\(SELECT|CAST)\s*\(/i

        // Database-specific system objects in malicious contexts
        $database_system_objects = /(\bSELECT [^;]*\b(information_schema|mysql\.user|all_tables|user_tables)\b|\bFROM\s+(information_schema|mysql\.user|dual|all_tables|user_tables)\b|LOAD_FILE\s*\(\s*['"][^'"]*\.(config|passwd|shadow|key)\b|INTO\s+OUTFILE\s+['"][^'"]*\.(txt|sql|php)\b|\b(xp_cmdshell|sp_executesql)\s*\(|dbms_[a-z_]+\s*\()/i

        // SQL injection with USER() function in malicious context
        $malicious_user_functions = /(\bUSER\s*\(\s*\)\s*(SELECT|FROM|WHERE|AND|OR|UNION)\b|CONCAT\s*\(\s*USER\s*\(\s*\))/i

        // Common SQL operation patterns that appear in both legitimate and malicious contexts
        $common_sql_ops = /(query_builder|sql_builder|orm_query|select_fields|insert_data|update_data|database_query|db_query|execute_query|prepared_statement|parameterized_query)/

        // Common context phrases where these words appear in benign usage
        $common_context_phrases = /\b(adds?\s+a\s+user|create\s+user|new\s+user|user\s+(account|profile|registration|authentication|permissions?|roles?)|user\s+(who|that)|for\s+user|the\s+user|current\s+user\s+(account|profile)|user\s+(input|data|information)|example:?\s+SELECT\s+USER\(\)|SELECT\s+USER\(\)\s+returns?|built-?in\s+function)\b/i

    condition:

        // Exclude Python sleep functions from all checks
        not $python_sleep and (

        // SQL injection tautologies
        ($injection_tautologies and not $common_sql_ops and not $common_context_phrases) or

        // Destructive SQL injections
        ($destructive_injections and not $common_sql_ops and not $common_context_phrases) or

        // Union-based attacks
        ($union_based_attacks and not $common_sql_ops and not $common_context_phrases) or

        // Time-based blind injection
        ($time_based_injections and not $common_sql_ops and not $common_context_phrases) or

        // Error-based injection techniques
        ($error_based_techniques and not $common_sql_ops and not $common_context_phrases) or

        // Database system object access
        ($database_system_objects and not $common_sql_ops and not $common_context_phrases) or

        // Malicious USER() function usage
        ($malicious_user_functions and not $common_sql_ops and not $common_context_phrases)

        )
}
