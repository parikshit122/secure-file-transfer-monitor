import React, { useState, useRef, useEffect } from 'react';
import { 
  RiUploadCloud2Line, 
  RiShieldCheckLine, 
  RiAlertLine, 
  RiFileWarningLine, 
  RiSearchEyeLine,
  RiRefreshLine,
  RiCheckDoubleLine
} from 'react-icons/ri';
import '../styles/scanner.css';

interface ScanResult {
  file_name: string;
  threat_score: number;
  verdict: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'ERROR';
  threats_detected: string[];
  details: string;
}

export const Scanner: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [stageText, setStageText] = useState<string>('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    return () => {
      setScanning(false);
      setProgress(0);
    };
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setResult(null);
      setErrorMessage(null);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      setResult(null);
      setErrorMessage(null);
    }
  };

  const startScan = async () => {
    if (!selectedFile) return;

    setScanning(true);
    setProgress(5);
    setStageText('Initializing Security Scanner Engine...');
    setErrorMessage(null);
    setResult(null);

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev < 30) {
          setStageText('Reading Magic Bytes & Entropy Analysis...');
          return prev + 15;
        } else if (prev < 60) {
          setStageText('Inspecting APK Permissions, Bytecode & Macros...');
          return prev + 15;
        } else if (prev < 85) {
          setStageText('Running YARA Secret Leak & Hash Comparison...');
          return prev + 10;
        }
        return prev;
      });
    }, 250);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        body: formData,
      });

      clearInterval(progressInterval);

      if (!response.ok) {
        throw new Error(`Server returned HTTP status ${response.status}`);
      }

      const data = (await response.json()) as ScanResult;
      setProgress(100);
      setStageText('Analysis Complete');
      
      setTimeout(() => {
        setResult(data);
        setScanning(false);
      }, 400);

    } catch (err: unknown) {
      clearInterval(progressInterval);
      setScanning(false);
      setProgress(0);
      const errMsg = err instanceof Error ? err.message : 'Failed to analyze file. Backend might be unreachable.';
      setErrorMessage(errMsg);
    }
  };

  const resetScanner = () => {
    setSelectedFile(null);
    setResult(null);
    setErrorMessage(null);
    setScanning(false);
    setProgress(0);
    setStageText('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="scanner-container">
      <header className="scanner-header">
        <div>
          <h2>Deep Heuristic File Scanner</h2>
          <p>Inspect APKs, Office Macros, Shannon Entropy & Embedded Malware Payloads</p>
        </div>
      </header>

      <div className="scanner-content">
        <div 
          className={`scanner-dropzone ${dragOver ? 'dragover' : ''} ${selectedFile ? 'has-file' : ''}`}
          onDragOver={(e: React.DragEvent<HTMLDivElement>) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => !scanning && fileInputRef.current?.click()}
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange} 
            style={{ display: 'none' }} 
            disabled={scanning}
          />

          <RiUploadCloud2Line className="upload-icon" />

          {selectedFile ? (
            <div className="file-preview">
              <p className="file-name">{selectedFile.name}</p>
              <p className="file-meta">{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</p>
            </div>
          ) : (
            <div>
              <h3>Drag and drop file here, or click to browse</h3>
              <p className="supported-formats">Supports .apk, .docm, .doc, .exe, .pdf, .zip, .txt and binary scripts</p>
            </div>
          )}
        </div>

        <div className="scanner-actions">
          {selectedFile && !scanning && !result && (
            <button className="btn-primary start-scan-btn" onClick={startScan}>
              <RiSearchEyeLine /> Run Deep Inspection Scan
            </button>
          )}

          {(selectedFile || result || errorMessage) && (
            <button className="btn-secondary reset-btn" onClick={resetScanner} disabled={scanning}>
              <RiRefreshLine /> Reset Scanner
            </button>
          )}
        </div>

        {scanning && (
          <div className="scanner-progress-container glass-card">
            <div className="progress-info">
              <span className="stage-text">{stageText}</span>
              <span className="progress-percentage">{progress}%</span>
            </div>
            <div className="progress-bar-track">
              <div className="progress-bar-fill" style={{ width: `${progress}%` }}></div>
            </div>
          </div>
        )}

        {errorMessage && (
          <div className="scanner-error-card">
            <RiFileWarningLine className="error-icon" />
            <div>
              <h4>Scan Execution Error</h4>
              <p>{errorMessage}</p>
            </div>
          </div>
        )}

        {result && (
          <div className={`scan-result-card glass-card verdict-${result.verdict.toLowerCase()}`}>
            <div className="result-header">
              <div className="verdict-badge">
                {result.verdict === 'BENIGN' && <RiShieldCheckLine className="badge-icon benign" />}
                {result.verdict === 'SUSPICIOUS' && <RiAlertLine className="badge-icon suspicious" />}
                {result.verdict === 'MALICIOUS' && <RiFileWarningLine className="badge-icon malicious" />}
                <div>
                  <h3>Verdict: {result.verdict}</h3>
                  <p>Analyzed File: {result.file_name}</p>
                </div>
              </div>
              <div className="score-box">
                <span className="score-val">{result.threat_score}</span>
                <span className="score-lbl">Threat Score / 100</span>
              </div>
            </div>

            <div className="threats-list-container">
              <h4>Threat Analysis Breakdown</h4>
              <ul>
                {result.threats_detected.map((t, idx) => (
                  <li key={idx} className="threat-item">
                    <RiCheckDoubleLine className="threat-bullet" />
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="result-details">
              <small>{result.details}</small>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Scanner;