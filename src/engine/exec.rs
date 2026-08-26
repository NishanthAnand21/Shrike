//! Async job runner. Spawns external commands, streams their stdout+stderr
//! line-by-line to the UI over an mpsc channel, enforces per-job timeouts,
//! supports cancellation, and bounds concurrency with a semaphore.

use crate::model::Phase;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

pub type JobId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Queued,
    Running,
    Done(i32),
    Failed,
    TimedOut,
    Cancelled,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, JobStatus::Queued | JobStatus::Running)
    }
    pub fn symbol(self) -> &'static str {
        match self {
            JobStatus::Queued => "…",
            JobStatus::Running => "▶",
            JobStatus::Done(0) => "✓",
            JobStatus::Done(_) => "✗",
            JobStatus::Failed => "✗",
            JobStatus::TimedOut => "⏱",
            JobStatus::Cancelled => "⊘",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    pub tool: String,
    pub phase: Phase,
    pub target: Option<String>,
    pub command: String,
    pub output_file: PathBuf,
    /// 0 = no timeout.
    pub timeout_secs: u64,
}

/// Streamed back to the UI. One job produces: Started, many Line, then Finished.
#[derive(Debug, Clone)]
pub enum JobEvent {
    Started {
        id: JobId,
    },
    Line {
        id: JobId,
        text: String,
    },
    Finished {
        id: JobId,
        status: JobStatus,
        duration_ms: u64,
    },
}

pub struct Runner {
    sem: Arc<Semaphore>,
    tx: mpsc::UnboundedSender<JobEvent>,
    cancels: Arc<tokio::sync::Mutex<std::collections::HashMap<JobId, CancellationToken>>>,
}

impl Runner {
    pub fn new(max_parallel: usize, tx: mpsc::UnboundedSender<JobEvent>) -> Self {
        Runner {
            sem: Arc::new(Semaphore::new(max_parallel.max(1))),
            tx,
            cancels: Arc::new(tokio::sync::Mutex::new(Default::default())),
        }
    }

    /// Queue a job. Returns immediately; progress arrives over the event channel.
    pub fn spawn(&self, job: Job) {
        let sem = self.sem.clone();
        let tx = self.tx.clone();
        let cancels = self.cancels.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore");
            let token = CancellationToken::new();
            cancels.lock().await.insert(job.id, token.clone());
            let start = std::time::Instant::now();
            let _ = tx.send(JobEvent::Started { id: job.id });

            let status = run_one(&job, &tx, token).await;

            cancels.lock().await.remove(&job.id);
            let _ = tx.send(JobEvent::Finished {
                id: job.id,
                status,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        });
    }

    pub async fn cancel(&self, id: JobId) {
        if let Some(tok) = self.cancels.lock().await.get(&id) {
            tok.cancel();
        }
    }

    pub async fn cancel_all(&self) {
        for tok in self.cancels.lock().await.values() {
            tok.cancel();
        }
    }

    pub async fn active(&self) -> usize {
        self.cancels.lock().await.len()
    }
}

async fn run_one(
    job: &Job,
    tx: &mpsc::UnboundedSender<JobEvent>,
    token: CancellationToken,
) -> JobStatus {
    // Run through a shell so operators can use pipes/redirection in templates.
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(&job.command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(JobEvent::Line {
                id: job.id,
                text: format!("!! failed to spawn: {e}"),
            });
            return JobStatus::Failed;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (line_tx, mut line_rx) = mpsc::unbounded_channel::<String>();

    if let Some(out) = stdout {
        let lt = line_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if lt.send(l).is_err() {
                    break;
                }
            }
        });
    }
    if let Some(err) = stderr {
        let lt = line_tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if lt.send(l).is_err() {
                    break;
                }
            }
        });
    }
    drop(line_tx);

    // Persist full output to disk as it streams.
    let mut file = tokio::fs::File::create(&job.output_file).await.ok();
    if let Some(f) = file.as_mut() {
        let header = format!("$ {}\n{}\n", job.command, "-".repeat(60));
        let _ = f.write_all(header.as_bytes()).await;
    }

    let deadline = if job.timeout_secs > 0 {
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(job.timeout_secs))
    } else {
        None
    };

    let mut timed_out = false;
    let mut cancelled = false;

    loop {
        let recv = line_rx.recv();
        tokio::pin!(recv);

        let step = async {
            match deadline {
                Some(d) => match tokio::time::timeout_at(d, &mut recv).await {
                    Ok(v) => Ok(v),
                    Err(_) => Err(()), // deadline
                },
                None => Ok((&mut recv).await),
            }
        };

        tokio::select! {
            _ = token.cancelled() => { cancelled = true; break; }
            r = step => match r {
                Ok(Some(line)) => {
                    if let Some(f) = file.as_mut() {
                        let _ = f.write_all(line.as_bytes()).await;
                        let _ = f.write_all(b"\n").await;
                    }
                    let _ = tx.send(JobEvent::Line { id: job.id, text: line });
                }
                Ok(None) => break, // pipes closed -> process finished
                Err(()) => { timed_out = true; break; }
            }
        }
    }

    if timed_out || cancelled {
        let _ = child.start_kill();
    }
    let exit = child.wait().await;

    if let Some(f) = file.as_mut() {
        let _ = f.flush().await;
    }

    if cancelled {
        JobStatus::Cancelled
    } else if timed_out {
        JobStatus::TimedOut
    } else {
        match exit {
            Ok(st) => JobStatus::Done(st.code().unwrap_or(-1)),
            Err(_) => JobStatus::Failed,
        }
    }
}
