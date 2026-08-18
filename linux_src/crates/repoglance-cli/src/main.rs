use std::{env, path::PathBuf};

use anyhow::Result;
use repoglance_core::scan_repository_path;

fn main() -> Result<()> {
    let path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?);
    let scan = scan_repository_path(0, &path)?;

    println!("Repository Health: {}/100", scan.score);
    println!("Current files:      {}", bytes(scan.working_tree_size));
    println!("Git history:        {}", bytes(scan.git_size));
    println!("Total size:         {}", bytes(scan.total_size));
    println!("Potential cleanup:  {}", bytes(scan.potential_cleanup));
    println!("Issues:             {}", scan.issue_count);

    for issue in scan.issues {
        println!("- {} ({})", issue.title, issue.affected_paths.len());
    }

    Ok(())
}

fn bytes(value: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < units.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if size >= 10.0 || unit == 0 {
        format!("{size:.0} {}", units[unit])
    } else {
        format!("{size:.1} {}", units[unit])
    }
}
