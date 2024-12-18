package Cx

import data.generic.ansible as ansible_lib

CxPolicy[result] {
    # Identify tasks using risky modules like 'reboot' or 'service'
    task := input.document[i].tasks[_]
    risky_module := {"reboot", "service"}

    task.module in risky_module

    # Additional safeguard: Ensure 'when' or 'check_mode' is present to reduce risks
    not task.when
    not task.check_mode

    result := {
        "documentId": input.document[i].id,
        "searchKey": sprintf("tasks[%d].module", [i]),
        "issueType": "RiskyAction",
        "keyExpectedValue": "Tasks using reboot or service modules must include safeguards like 'when' or 'check_mode'.",
        "keyActualValue": sprintf("Task with module '%s' has no safeguards.", [task.module]),
    }
}

CxPolicy[result] {
    # Identify tasks modifying critical files or configurations
    task := input.document[i].tasks[_]
    file_paths := task.args.dest

    # Detect if paths are critical (e.g., /etc/passwd, /etc/nginx/nginx.conf)
    critical_paths := {"/etc/passwd", "/etc/nginx/nginx.conf", "/var/www/html"}

    file_paths in critical_paths

    # Check if a backup is created or validation is performed
    not task.args.backup

    result := {
        "documentId": input.document[i].id,
        "searchKey": sprintf("tasks[%d].args.dest", [i]),
        "issueType": "CriticalModification",
        "keyExpectedValue": "Modifications to critical files should include a backup.",
        "keyActualValue": sprintf("Task modifies critical file '%s' without backup.", [file_paths]),
    }
}
