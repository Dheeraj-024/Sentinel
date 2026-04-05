import { useState, useCallback, useRef, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { GoogleGenAI, Type, ThinkingLevel } from "@google/genai";
import { motion, AnimatePresence } from "motion/react";
import emailjs from '@emailjs/browser';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Upload, 
  Video, 
  AlertTriangle, 
  Activity, 
  Eye, 
  Clock, 
  ChevronRight,
  Loader2,
  X,
  Camera,
  Timer,
  User,
  Car,
  AlertCircle,
  MessageSquare,
  RefreshCw,
  Monitor,
  MonitorOff,
  Mic,
  MicOff,
  Volume2,
  History,
  Radio,
  Database,
  Zap,
  Bell,
  Search,
  Trash2,
  Mail,
  LayoutGrid
} from "lucide-react";
import { cn } from "@/src/lib/utils";
import { 
  FileSecurityAnalysis, 
  LiveSecurityAnalysis, 
  ThreatEvent, 
  SecurityEvent,
  SubjectTracked
} from "@/src/types";

const FILE_SYSTEM_INSTRUCTION = `SYSTEM ROLE: 
You are Sentinel AI Core, a highly analytical, zero-hallucination security engine analyzing enterprise surveillance feeds.

CORE DIRECTIVES:
1. TEMPORAL PRECISION: You must identify the exact onset (MM:SS) of any anomaly. 
2. NOISE CANCELLATION: ABSOLUTELY IGNORE weather, shadows, camera glitches, and small animals (cats, dogs, birds, rodents). Do not report them as events. Only track humans, vehicles, and structural breaches.
3. CONTEXTUAL REASONING: Differentiate between authorized personnel (e.g., uniforms, badges, predictable walking paths) and intruders (e.g., face concealment, erratic movement, unauthorized entry points).
4. SPATIAL COORDINATES: For every event, provide the approximate center (x, y) coordinates (0-100 percentage of frame) where the primary activity is occurring.
5. THREAT FOCUS: Prioritize reporting SUSPICIOUS or CRITICAL events. If an event is not clearly suspicious or critical, and is not a human/vehicle, ignore it.
6. STRICT OUTPUT: You will output ONLY valid, minified JSON. Absolutely no conversational text, no markdown blocks (do not use \`\`\`json), and no introductory phrases.

INPUT VARIABLES EXPECTED (Passed with video):
- Camera_ID
- Base_Time

JSON SCHEMA STRICT REQUIREMENT:
{
  "camera_id": "string (extract from input or default to UNKNOWN)",
  "analysis_status": "SUCCESS" | "NO_ANOMALY",
  "events": [
    {
      "classification": "BENIGN" | "SUSPICIOUS" | "CRITICAL",
      "threat_level": integer (1-10),
      "confidence_score": float (0.00 to 1.00),
      "spatial_coordinates": { "x": number (0-100), "y": number (0-100) },
      "timestamps": {
        "event_onset": "MM:SS (exact second the anomaly begins)",
        "event_conclusion": "MM:SS (exact second the anomaly ends or video ends)"
      },
      "subjects_tracked": [
        {
          "type": "PERSON" | "VEHICLE",
          "description": "Concise physical description",
          "concealment_detected": boolean
        }
      ],
      "action_required": "IGNORE" | "LOG" | "DISPATCH_AUTHORITIES",
      "soc_justification": "One sentence strictly explaining the threat level."
    }
  ]
}

FAIL-SAFE: If no event is detected, return threat_level 1, classification BENIGN, and action_required IGNORE. Output JSON only.`;

const LIVE_SYSTEM_INSTRUCTION = `ACT AS: A Senior Lead Security Analyst for a high-security facility.
TASK: Analyze the provided video and audio feed and return a strictly formatted JSON object.

EVALUATION CRITERIA:
1. SPATIAL AWARENESS: Identify ALL living beings (humans, animals) in the frame.
2. BEHAVIORAL ANALYSIS: Distinguish between routine movement and aggressive/suspicious movement.
3. AUDIO ANALYSIS: Detect and identify sounds like gunshots, glass breaking, distress shouts, or suspicious whispering.
4. MULTI-MODAL FUSION: Combine visual and audio cues to determine the overall threat level.
5. PRIMARY DESIGNATION: You MUST designate exactly ONE individual as "is_primary: true". This should be the individual performing the most suspicious or high-threat activity.
6. OBJECT DETECTION: Provide 2D bounding boxes [ymin, xmin, ymax, xmax] for ALL detected subjects.

OUTPUT FORMAT (STRICT JSON ONLY):
{
  "analysis": {
    "subjects_detected": ["list", "of", "entities"],
    "primary_activity": "Short description of the most critical action",
    "is_authorized_behavior": boolean,
    "confidence_score": float (0.0 to 1.0),
    "subjects": [
      {
        "box_2d": [ymin, xmin, ymax, xmax],
        "label": "subject label",
        "is_primary": boolean,
        "threat_contribution": "Short reason"
      }
    ],
    "audio_analysis": {
      "detected_sounds": ["list", "of", "sounds"],
      "threat_level": integer (1-10),
      "description": "Summary of audio activity"
    }
  },
  "threat_assessment": {
    "level": integer (1-10),
    "indicators": ["reason 1", "reason 2"],
    "status": "BENIGN" | "SUSPICIOUS" | "CRITICAL"
  },
  "recommendation": {
    "action": "IGNORE" | "LOG" | "DISPATCH_AUTHORITIES",
    "justification": "Clear reasoning"
  }
}

CONSTRAINT: If a gunshot or scream is heard, elevate threat level immediately. Do not include markdown formatting or any conversational text.`;

interface Feed {
  id: string;
  file: File;
  url: string;
  cameraId: string;
  baseTime: string;
  analysis: FileSecurityAnalysis | null;
  isAnalyzing: boolean;
  isProcessing: boolean;
  processingProgress: number;
  error: string | null;
  feedback?: string;
}

type AppMode = 'FILE' | 'LIVE';

export default function App() {
  // Global State
  const [mode, setMode] = useState<AppMode>('FILE');

  // File Mode State
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [globalIsAnalyzing, setGlobalIsAnalyzing] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [showHeatmap, setShowHeatmap] = useState(true);
  const [filterThreatLevels, setFilterThreatLevels] = useState<string[]>(['BENIGN', 'SUSPICIOUS', 'CRITICAL']);
  const [filterTimeRange, setFilterTimeRange] = useState<[number, number]>([0, 3600]);

  // Live Mode State
  const [isAnalyzingLive, setIsAnalyzingLive] = useState(false);
  const [liveAnalysis, setLiveAnalysis] = useState<LiveSecurityAnalysis | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [lastAnalysisTime, setLastAnalysisTime] = useState<Date | null>(null);
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<ThreatEvent | null>(null);
  const [isAudioEnabled, setIsAudioEnabled] = useState(false);
  const [audioStream, setAudioStream] = useState<MediaStream | null>(null);
  const [audioFrequencies, setAudioFrequencies] = useState<number[]>(new Array(32).fill(0));
  const [mediaRecorder, setMediaRecorder] = useState<MediaRecorder | null>(null);

  // Email Notification State
  const [gmailId, setGmailId] = useState<string>("");
  const [showGmailInput, setShowGmailInput] = useState(false);
  const [showSuccessPopup, setShowSuccessPopup] = useState(false);
  const [savedGmailId, setSavedGmailId] = useState<string>("");
  const [emailPopupMessage, setEmailPopupMessage] = useState<string | null>(null);
  
  const [systemStatus, setSystemStatus] = useState<'HEALTHY' | 'WARNING' | 'ERROR'>('HEALTHY');
  const [lastHealthCheck, setLastHealthCheck] = useState<Date | null>(null);
  const [systemLogs, setSystemLogs] = useState<{id: string, time: string, msg: string, type: 'INFO' | 'WARN' | 'ERROR'}[]>([]);

  const checkSystemHealth = useCallback(async () => {
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });
      // Minimal check to see if API is reachable
      await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: "health check",
        config: { maxOutputTokens: 1 }
      });
      setSystemStatus('HEALTHY');
      setLastHealthCheck(new Date());
    } catch (err) {
      console.error("Health check failed:", err);
      setSystemStatus('WARNING');
      addLog("System health check failed. API may be unreachable.", "WARN");
    }
  }, []);

  useEffect(() => {
    checkSystemHealth();
    const interval = setInterval(checkSystemHealth, 300000); // Every 5 minutes
    return () => clearInterval(interval);
  }, [checkSystemHealth]);

  const addLog = useCallback((msg: string, type: 'INFO' | 'WARN' | 'ERROR' = 'INFO') => {
    const newLog = {
      id: Math.random().toString(36).substring(7),
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
      msg,
      type
    };
    setSystemLogs(prev => [newLog, ...prev].slice(0, 50));
  }, []);

  const [isTestingEmail, setIsTestingEmail] = useState(false);

  const testEmailNotification = async () => {
    if (!savedGmailId) return;
    setIsTestingEmail(true);
    addLog(`Sending test notification to ${savedGmailId}...`, "INFO");
    try {
      await sendThreatNotification(
        1,
        "TEST_SUBJECT",
        "This is a system test of the Sentinel AI notification engine.",
        "LOG",
        "System Diagnostic",
        new Date().toLocaleString()
      );
      addLog("Test notification sent successfully.", "INFO");
    } catch (err) {
      addLog("Test notification failed.", "ERROR");
    } finally {
      setIsTestingEmail(false);
    }
  };

  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const monitoringIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const audioAnalyserRef = useRef<AnalyserNode | null>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  // --- Shared Effects & Cleanup ---

  useEffect(() => {
    const saved = localStorage.getItem('sentinel-gmail-id');
    if (saved) {
      setSavedGmailId(saved);
      setGmailId(saved);
    }
    addLog("System initialized. Core engine online.", "INFO");
  }, [addLog]);

  useEffect(() => {
    return () => {
      if (stream) stream.getTracks().forEach(track => track.stop());
      if (audioStream) audioStream.getTracks().forEach(track => track.stop());
      if (monitoringIntervalRef.current) clearInterval(monitoringIntervalRef.current);
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
      if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
        audioContextRef.current.close();
      }
    };
  }, [stream, audioStream]);

  useEffect(() => {
    if (mode === 'LIVE' && stream && videoRef.current) {
      videoRef.current.srcObject = stream;
      videoRef.current.play().catch(err => console.error("Autoplay failed:", err));
    }
  }, [mode, stream]);

  // --- File Mode Functions ---

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const newFeeds: Feed[] = acceptedFiles.map((file) => ({
      id: Math.random().toString(36).substring(7),
      file,
      url: URL.createObjectURL(file),
      cameraId: `CAM-${Math.floor(Math.random() * 900) + 100}`,
      baseTime: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }),
      analysis: null,
      isAnalyzing: false,
      isProcessing: false,
      processingProgress: 0,
      error: null
    }));
    setFeeds(prev => [...prev, ...newFeeds]);
    addLog(`Added ${acceptedFiles.length} new surveillance feed(s).`, "INFO");
  }, [addLog]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 
      'video/*': [],
      'image/*': ['.jpeg', '.jpg', '.png', '.webp']
    },
    multiple: true
  } as any);

  const removeFeed = (id: string) => {
    setFeeds(prev => {
      const feed = prev.find(f => f.id === id);
      if (feed) {
        URL.revokeObjectURL(feed.url);
        addLog(`Removed feed: ${feed.cameraId}`, "INFO");
      }
      return prev.filter(f => f.id !== id);
    });
  };

  const captureFramesFromVideo = async (feedId: string, file: File, frameCount: number = 6): Promise<{ data: string, mimeType: string }[]> => {
    return new Promise((resolve, reject) => {
      const video = document.createElement('video');
      video.preload = 'metadata';
      video.src = URL.createObjectURL(file);
      video.muted = true;
      video.playsInline = true;

      video.onloadedmetadata = async () => {
        const duration = video.duration;
        const frames: { data: string, mimeType: string }[] = [];
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) { reject(new Error("Failed to get canvas context")); return; }

        const MAX_WIDTH = 768;
        const scale = Math.min(1, MAX_WIDTH / video.videoWidth);
        canvas.width = video.videoWidth * scale;
        canvas.height = video.videoHeight * scale;

        try {
          for (let i = 0; i < frameCount; i++) {
            setFeeds(prev => prev.map(f => f.id === feedId ? { ...f, processingProgress: Math.round(((i + 1) / frameCount) * 100) } : f));
            const time = (duration / (frameCount + 1)) * (i + 1);
            video.currentTime = time;
            await new Promise((res, rej) => {
              const timeout = setTimeout(() => rej(new Error("Seek timeout")), 5000);
              const onSeeked = () => {
                clearTimeout(timeout);
                video.removeEventListener('seeked', onSeeked);
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                frames.push({ data: canvas.toDataURL('image/jpeg', 0.7).split(',')[1], mimeType: 'image/jpeg' });
                res(null);
              };
              video.addEventListener('seeked', onSeeked);
            });
          }
          URL.revokeObjectURL(video.src);
          resolve(frames);
        } catch (err) {
          URL.revokeObjectURL(video.src);
          reject(err);
        }
      };
      video.onerror = () => { URL.revokeObjectURL(video.src); reject(new Error("Failed to load video file")); };
    });
  };

  const sendThreatNotification = async (
    threatLevel: number, 
    subject: string, 
    reasoning: string, 
    action: string, 
    source: string,
    timestamp: string
  ) => {
    if (!savedGmailId) return;

    const serviceId = import.meta.env.VITE_EMAILJS_SERVICE_ID;
    const templateId = import.meta.env.VITE_EMAILJS_TEMPLATE_ID;
    const publicKey = import.meta.env.VITE_EMAILJS_PUBLIC_KEY;

    if (!serviceId || !templateId || !publicKey) {
      // Only log the error if we are in a situation where we *should* be sending an email
      // and the settings are missing.
      if (threatLevel >= 5) {
        console.error('EmailJS settings are missing. Please configure VITE_EMAILJS_SERVICE_ID, VITE_EMAILJS_TEMPLATE_ID, and VITE_EMAILJS_PUBLIC_KEY in the Secrets panel.');
      }
      return;
    }

    try {
      const templateParams = {
        to_email: savedGmailId,
        threat_level: threatLevel,
        primary_subject: subject,
        contextual_reasoning: reasoning,
        recommended_action: action.replace('_', ' '),
        source: source,
        timestamp: timestamp,
      };

      emailjs.init(publicKey);
      await emailjs.send(serviceId, templateId, templateParams, publicKey);
      
      setEmailPopupMessage(`Threat Alert sent to ${savedGmailId}`);
      setTimeout(() => setEmailPopupMessage(null), 4000);
    } catch (error) {
      console.error('Failed to send threat notification email:', error);
    }
  };

  const analyzeFeed = async (feedId: string) => {
    const feed = feeds.find(f => f.id === feedId);
    if (!feed) return;

    setFeeds(prev => prev.map(f => f.id === feedId ? { ...f, isAnalyzing: true, isProcessing: true, processingProgress: 0, error: null } : f));
    addLog(`Starting deep analysis for feed: ${feed.cameraId}`, "INFO");

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });
      let parts: any[] = [];

      if (feed.file.type.startsWith('image/')) {
        const reader = new FileReader();
        const base64Promise = new Promise<string>((resolve) => {
          reader.onload = () => resolve((reader.result as string).split(',')[1]);
          reader.readAsDataURL(feed.file);
        });
        const base64Data = await base64Promise;
        parts = [
          { text: `Analyze this security image. Camera_ID: ${feed.cameraId}, Base_Time: ${feed.baseTime}${feed.feedback ? `. USER FEEDBACK/FOCUS: ${feed.feedback}. Please pay special attention to this feedback and re-evaluate the image accordingly.` : ""}` },
          { inlineData: { mimeType: feed.file.type, data: base64Data } }
        ];
      } else {
        const frames = await captureFramesFromVideo(feedId, feed.file);
        parts = [
          { text: `Analyze these sequential frames from a security video. Camera_ID: ${feed.cameraId}, Base_Time: ${feed.baseTime}${feed.feedback ? `. USER FEEDBACK/FOCUS: ${feed.feedback}. Please pay special attention to this feedback and re-evaluate the footage accordingly.` : ""}` },
          ...frames.map(f => ({ inlineData: f }))
        ];
      }

      setFeeds(prev => prev.map(f => f.id === feedId ? { ...f, isProcessing: false } : f));

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: [{ parts }],
        config: {
          systemInstruction: FILE_SYSTEM_INSTRUCTION,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              camera_id: { type: Type.STRING },
              analysis_status: { type: Type.STRING, enum: ["SUCCESS", "NO_ANOMALY"] },
              events: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    classification: { type: Type.STRING, enum: ["BENIGN", "SUSPICIOUS", "CRITICAL"] },
                    threat_level: { type: Type.INTEGER },
                    confidence_score: { type: Type.NUMBER },
                    spatial_coordinates: {
                      type: Type.OBJECT,
                      properties: { x: { type: Type.NUMBER }, y: { type: Type.NUMBER } },
                      required: ["x", "y"],
                    },
                    timestamps: {
                      type: Type.OBJECT,
                      properties: { event_onset: { type: Type.STRING }, event_conclusion: { type: Type.STRING } },
                      required: ["event_onset", "event_conclusion"],
                    },
                    subjects_tracked: {
                      type: Type.ARRAY,
                      items: {
                        type: Type.OBJECT,
                        properties: {
                          type: { type: Type.STRING, enum: ["PERSON", "VEHICLE"] },
                          description: { type: Type.STRING },
                          concealment_detected: { type: Type.BOOLEAN },
                        },
                        required: ["type", "description", "concealment_detected"],
                      },
                    },
                    action_required: { type: Type.STRING, enum: ["IGNORE", "LOG", "DISPATCH_AUTHORITIES"] },
                    soc_justification: { type: Type.STRING },
                  },
                  required: ["classification", "threat_level", "confidence_score", "timestamps", "subjects_tracked", "action_required", "soc_justification"],
                },
              },
            },
            required: ["camera_id", "analysis_status", "events"],
          },
        },
      });

      const result = JSON.parse(response.text || "{}") as FileSecurityAnalysis;
      setFeeds(prev => prev.map(f => f.id === feedId ? { ...f, analysis: result, isAnalyzing: false } : f));
      addLog(`Analysis complete for ${feed.cameraId}. Status: ${result.analysis_status}`, result.analysis_status === 'SUCCESS' ? 'INFO' : 'WARN');

      // Send email notification for high threat levels
      result.events.forEach(event => {
        if (event.threat_level >= 5) {
          sendThreatNotification(
            event.threat_level,
            event.subjects_tracked.map(s => s.description).join(', '),
            event.soc_justification,
            event.action_required,
            `File Feed: ${feed.cameraId}`,
            `${event.timestamps.event_onset} (Video Time)`
          );
        }
      });
    } catch (err: any) {
      console.error("Analysis failed:", err);
      setFeeds(prev => prev.map(f => f.id === feedId ? { ...f, error: err.message || "Analysis failed", isAnalyzing: false, isProcessing: false } : f));
      addLog(`Analysis failed for ${feed.cameraId}: ${err.message}`, "ERROR");
      setSystemStatus('WARNING');
    }
  };

  // --- Live Mode Functions ---

  const startLiveMode = async () => {
    try {
      addLog("Requesting camera access...", "INFO");
      const mediaStream = await navigator.mediaDevices.getUserMedia({ 
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } } 
      });
      setStream(mediaStream);
      setLiveAnalysis(null);
      setLiveError(null);
      addLog("Camera connected successfully.", "INFO");
    } catch (err) {
      console.error("Failed to access camera:", err);
      setLiveError("Camera access denied. Please check permissions.");
      addLog("Camera access denied.", "ERROR");
      setSystemStatus('ERROR');
    }
  };

  const toggleAudio = async () => {
    if (isAudioEnabled) {
      addLog("Disabling audio monitoring.", "INFO");
      if (audioStream) audioStream.getTracks().forEach(track => track.stop());
      if (audioContextRef.current && audioContextRef.current.state !== 'closed') audioContextRef.current.close();
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current);
      setAudioStream(null);
      setIsAudioEnabled(false);
      setAudioFrequencies(new Array(32).fill(0));
    } else {
      try {
        addLog("Requesting microphone access...", "INFO");
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        setAudioStream(stream);
        setIsAudioEnabled(true);
        addLog("Audio monitoring enabled.", "INFO");
        const audioContext = new AudioContext();
        audioContextRef.current = audioContext;
        const source = audioContext.createMediaStreamSource(stream);
        const analyser = audioContext.createAnalyser();
        analyser.fftSize = 256;
        source.connect(analyser);
        audioAnalyserRef.current = analyser;
        const recorder = new MediaRecorder(stream);
        setMediaRecorder(recorder);
        const updateLevel = () => {
          const dataArray = new Uint8Array(analyser.frequencyBinCount);
          analyser.getByteFrequencyData(dataArray);
          
          // Group into 32 frequency bands
          const bands = 32;
          const samplesPerBand = Math.floor(dataArray.length / bands);
          const newFrequencies = [];
          for (let i = 0; i < bands; i++) {
            let sum = 0;
            for (let j = 0; j < samplesPerBand; j++) {
              sum += dataArray[i * samplesPerBand + j];
            }
            // Use a slight logarithmic scale for better visualization
            const avg = sum / samplesPerBand / 255;
            newFrequencies.push(Math.pow(avg, 0.8));
          }
          setAudioFrequencies(newFrequencies);
          animationFrameRef.current = requestAnimationFrame(updateLevel);
        };
        updateLevel();
      } catch (err) {
        console.error("Failed to access microphone:", err);
        setLiveError("Microphone access denied.");
      }
    }
  };

  const captureLiveFrame = (): string | null => {
    if (!videoRef.current || !canvasRef.current) return null;
    const canvas = canvasRef.current;
    const video = videoRef.current;
    const MAX_WIDTH = 512;
    const scale = MAX_WIDTH / video.videoWidth;
    canvas.width = MAX_WIDTH;
    canvas.height = video.videoHeight * scale;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL('image/jpeg', 0.6).split(',')[1];
  };

  const analyzeLiveFrame = async (base64Data: string) => {
    setIsAnalyzingLive(true);
    setLiveError(null);
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });
      const contents: any[] = [{
        parts: [
          { text: "Analyze this security footage frame and audio for potential threats. Identify ALL subjects and designate the primary threat. Fuse visual and audio data." },
          { inlineData: { mimeType: "image/jpeg", data: base64Data } },
        ],
      }];

      if (isAudioEnabled && mediaRecorder) {
        mediaRecorder.start();
        const audioBlob = await new Promise<Blob>((resolve) => {
          setTimeout(() => {
            mediaRecorder.addEventListener('dataavailable', (e) => resolve(e.data), { once: true });
            mediaRecorder.stop();
          }, 500);
        });
        const audioBase64 = await new Promise<string>((resolve) => {
          const reader = new FileReader();
          reader.onloadend = () => resolve((reader.result as string).split(',')[1]);
          reader.readAsDataURL(audioBlob);
        });
        contents[0].parts.push({ inlineData: { mimeType: "audio/webm", data: audioBase64 } });
      }

      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: contents,
        config: {
          systemInstruction: LIVE_SYSTEM_INSTRUCTION,
          responseMimeType: "application/json",
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              analysis: {
                type: Type.OBJECT,
                properties: {
                  subjects_detected: { type: Type.ARRAY, items: { type: Type.STRING } },
                  primary_activity: { type: Type.STRING },
                  is_authorized_behavior: { type: Type.BOOLEAN },
                  confidence_score: { type: Type.NUMBER },
                  subjects: {
                    type: Type.ARRAY,
                    items: {
                      type: Type.OBJECT,
                      properties: {
                        box_2d: { type: Type.ARRAY, items: { type: Type.NUMBER } },
                        label: { type: Type.STRING },
                        is_primary: { type: Type.BOOLEAN },
                        threat_contribution: { type: Type.STRING }
                      },
                      required: ["box_2d", "label", "is_primary", "threat_contribution"]
                    }
                  },
                  audio_analysis: {
                    type: Type.OBJECT,
                    properties: {
                      detected_sounds: { type: Type.ARRAY, items: { type: Type.STRING } },
                      threat_level: { type: Type.INTEGER },
                      description: { type: Type.STRING }
                    },
                    required: ["detected_sounds", "threat_level", "description"]
                  }
                },
                required: ["subjects_detected", "primary_activity", "is_authorized_behavior", "confidence_score", "subjects"],
              },
              threat_assessment: {
                type: Type.OBJECT,
                properties: {
                  level: { type: Type.INTEGER },
                  indicators: { type: Type.ARRAY, items: { type: Type.STRING } },
                  status: { type: Type.STRING, enum: ["BENIGN", "SUSPICIOUS", "CRITICAL"] },
                },
                required: ["level", "indicators", "status"],
              },
              recommendation: {
                type: Type.OBJECT,
                properties: {
                  action: { type: Type.STRING, enum: ["IGNORE", "LOG", "DISPATCH_AUTHORITIES"] },
                  justification: { type: Type.STRING },
                },
                required: ["action", "justification"],
              },
            },
            required: ["analysis", "threat_assessment", "recommendation"],
          },
        },
      });

      const result = JSON.parse(response.text || "{}") as LiveSecurityAnalysis;
      setLiveAnalysis(result);
      setLastAnalysisTime(new Date());
      addLog(`Live analysis complete. Threat Level: ${result.threat_assessment.level}`, result.threat_assessment.level >= 5 ? 'WARN' : 'INFO');

      if (result.threat_assessment.level >= 5) {
        addLog(`CRITICAL THREAT DETECTED: ${result.analysis.primary_activity}`, "ERROR");
        setThreatEvents(prev => [{
          id: Math.random().toString(36).substr(2, 9),
          timestamp: new Date(),
          snapshot: `data:image/jpeg;base64,${base64Data}`,
          analysis: result
        }, ...prev].slice(0, 50));

        // Send email notification
        sendThreatNotification(
          result.threat_assessment.level,
          result.analysis.primary_activity,
          result.recommendation.justification,
          result.recommendation.action,
          "Live Feed: Primary Camera",
          new Date().toLocaleString()
        );
      }
    } catch (err: any) {
      console.error("Live analysis failed:", err);
      setLiveError(err.message || "Live analysis failed");
      addLog(`Live analysis failed: ${err.message}`, "ERROR");
      setSystemStatus('WARNING');
    } finally {
      setIsAnalyzingLive(false);
    }
  };

  const toggleMonitoring = () => {
    if (isMonitoring) {
      addLog("Stopping live monitoring.", "INFO");
      if (monitoringIntervalRef.current) clearInterval(monitoringIntervalRef.current);
      setIsMonitoring(false);
    } else {
      addLog("Starting live monitoring cycle.", "INFO");
      setIsMonitoring(true);
      const frame = captureLiveFrame();
      if (frame) analyzeLiveFrame(frame);
      monitoringIntervalRef.current = setInterval(() => {
        const frame = captureLiveFrame();
        if (frame) analyzeLiveFrame(frame);
      }, 3000);
    }
  };

  // --- Shared UI Helpers ---

  const [eventSearch, setEventSearch] = useState("");

  const getThreatColor = (level: number) => {
    if (level <= 3) return "text-emerald-400 bg-emerald-400/10 border-emerald-400/20";
    if (level <= 7) return "text-amber-400 bg-amber-400/10 border-amber-400/20";
    return "text-rose-400 bg-rose-400/10 border-rose-400/20";
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'BENIGN': return "text-emerald-400 bg-emerald-400/10 border-emerald-400/20";
      case 'SUSPICIOUS': return "text-amber-400 bg-amber-400/10 border-amber-400/20";
      case 'CRITICAL': return "text-rose-400 bg-rose-400/10 border-rose-400/20";
      default: return "text-slate-400 bg-slate-400/10 border-slate-400/20";
    }
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'IGNORE': return <ShieldCheck className="w-5 h-5" />;
      case 'LOG': return <Shield className="w-5 h-5" />;
      case 'DISPATCH_AUTHORITIES': return <ShieldAlert className="w-5 h-5" />;
      default: return <Shield className="w-5 h-5" />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-slate-200 font-sans selection:bg-indigo-500/30">
      <header className="border-b border-white/5 bg-black/40 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <Shield className="text-white w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-lg tracking-tight text-white uppercase tracking-wider flex items-center gap-2">
                Sentinel AI <span className="text-[10px] bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-500/30">CORE</span>
              </h1>
              <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-semibold">Surveillance Engine</p>
            </div>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center bg-white/5 p-1 rounded-xl border border-white/10">
            <button 
              onClick={() => setMode('FILE')}
              className={cn(
                "flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-widest transition-all",
                mode === 'FILE' ? "bg-indigo-600 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"
              )}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              File Feed
            </button>
            <button 
              onClick={() => setMode('LIVE')}
              className={cn(
                "flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-widest transition-all",
                mode === 'LIVE' ? "bg-rose-600 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"
              )}
            >
              <Radio className="w-3.5 h-3.5" />
              Live Feed
            </button>
          </div>

          <div className="flex items-center gap-4">
            <div className="group relative flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 border border-white/10">
              <div className={cn("w-2 h-2 rounded-full animate-pulse", 
                systemStatus === 'HEALTHY' ? "bg-emerald-500" : 
                systemStatus === 'WARNING' ? "bg-amber-500" : "bg-rose-500"
              )} />
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                System: {systemStatus}
              </span>
              
              {/* Status Tooltip */}
              <div className="absolute top-full left-0 mt-2 w-48 p-3 rounded-xl bg-slate-900 border border-white/10 shadow-2xl opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50">
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-[9px] text-slate-500 uppercase font-bold">Engine</span>
                    <span className="text-[9px] text-emerald-400 font-bold">ACTIVE</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[9px] text-slate-500 uppercase font-bold">Last Check</span>
                    <span className="text-[9px] text-slate-300 font-mono">{lastHealthCheck?.toLocaleTimeString([], { hour12: false }) || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[9px] text-slate-500 uppercase font-bold">Latency</span>
                    <span className="text-[9px] text-indigo-400 font-mono">~140ms</span>
                  </div>
                </div>
              </div>
            </div>
            <button
              onClick={() => setShowGmailInput(!showGmailInput)}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200 hover:shadow-lg hover:shadow-slate-900/20",
                savedGmailId 
                  ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20" 
                  : "bg-slate-800/50 border border-slate-700/50 text-slate-300 hover:bg-slate-700/50 hover:border-slate-600/50"
              )}
            >
              <Mail className="w-4 h-4" />
              <span className="text-sm font-medium">
                {savedGmailId ? "Gmail Configured" : "Gmail ID"}
              </span>
            </button>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-[11px] font-medium text-emerald-400 uppercase tracking-wider">
                {mode === 'FILE' ? 'Core Online' : 'Monitoring Active'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Gmail ID Section */}
      <AnimatePresence>
        {showGmailInput && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            className="border-b border-white/5 bg-slate-900/20 backdrop-blur-sm overflow-hidden"
          >
            <div className="max-w-7xl mx-auto px-6 py-4">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-3 flex-1 max-w-md">
                  <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
                    <Mail className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="flex-1">
                    <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">
                      Notification Endpoint (Gmail)
                    </label>
                    <div className="flex items-center gap-2">
                      <input
                        type="email"
                        value={gmailId}
                        onChange={(e) => setGmailId(e.target.value)}
                        placeholder="e.g. security@sentinel.com"
                        className="flex-1 px-4 py-2 bg-black/40 border border-white/10 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all text-sm"
                      />
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      if (gmailId.trim()) {
                        localStorage.setItem('sentinel-gmail-id', gmailId.trim());
                        setSavedGmailId(gmailId.trim());
                        setShowGmailInput(false);
                        setShowSuccessPopup(true);
                        addLog(`Gmail ID updated: ${gmailId.trim()}`, "INFO");
                        setTimeout(() => setShowSuccessPopup(false), 3000);
                      }
                    }}
                    disabled={!gmailId.trim()}
                    className="px-6 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-600 disabled:cursor-not-allowed text-white text-xs font-bold uppercase tracking-widest transition-all shadow-lg shadow-indigo-600/20"
                  >
                    Save
                  </button>
                  {savedGmailId && (
                    <button
                      onClick={testEmailNotification}
                      disabled={isTestingEmail}
                      className="px-6 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 text-xs font-bold uppercase tracking-widest transition-all flex items-center gap-2"
                    >
                      {isTestingEmail ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                      Test
                    </button>
                  )}
                  <button
                    onClick={() => setShowGmailInput(false)}
                    className="px-6 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-slate-400 text-xs font-bold uppercase tracking-widest transition-all"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Quick Actions Bar */}
        <div className="mb-8 flex flex-wrap items-center gap-4 p-4 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-sm">
          <div className="flex items-center gap-2 pr-4 border-r border-white/10">
            <Activity className="w-4 h-4 text-indigo-400" />
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Quick Actions</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button 
              onClick={() => feeds.filter(f => !f.analysis).forEach(f => analyzeFeed(f.id))} 
              disabled={globalIsAnalyzing || feeds.length === 0} 
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-[10px] font-bold uppercase tracking-widest transition-all shadow-lg shadow-indigo-600/20"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", globalIsAnalyzing && "animate-spin")} />
              Analyze All
            </button>
            <button 
              onClick={() => setFeeds([])} 
              disabled={feeds.length === 0}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 text-[10px] font-bold uppercase tracking-widest transition-all"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear Grid
            </button>
            <button 
              onClick={() => {
                const logText = systemLogs.map(l => `[${l.time}] ${l.type}: ${l.msg}`).join('\n');
                const blob = new Blob([logText], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `sentinel-logs-${new Date().toISOString().split('T')[0]}.txt`;
                a.click();
                addLog("System logs exported.", "INFO");
              }}
              disabled={systemLogs.length === 0}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 text-[10px] font-bold uppercase tracking-widest transition-all"
            >
              <Upload className="w-3.5 h-3.5 rotate-180" />
              Export Logs
            </button>
          </div>
        </div>

        {mode === 'FILE' ? (
          // --- FILE MODE UI ---
          <>
            <div className="mb-8 grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 flex flex-col gap-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Active Feeds</span>
                <span className="text-2xl font-black text-white">{feeds.length}</span>
              </div>
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 flex flex-col gap-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Critical Alerts</span>
                <span className="text-2xl font-black text-rose-500">
                  {feeds.reduce((acc, f) => acc + (f.analysis?.events.filter(e => e.classification === 'CRITICAL').length || 0), 0)}
                </span>
              </div>
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 flex flex-col gap-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Suspicious Activity</span>
                <span className="text-2xl font-black text-amber-500">
                  {feeds.reduce((acc, f) => acc + (f.analysis?.events.filter(e => e.classification === 'SUSPICIOUS').length || 0), 0)}
                </span>
              </div>
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 flex flex-col gap-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Avg Confidence</span>
                <span className="text-2xl font-black text-indigo-400">
                  {feeds.length > 0 ? (
                    (feeds.reduce((acc, f) => acc + (f.analysis?.events.reduce((eAcc, e) => eAcc + e.confidence_score, 0) || 0), 0) / 
                    (feeds.reduce((acc, f) => acc + (f.analysis?.events.length || 0), 0) || 1) * 100).toFixed(0)
                  ) : 0}%
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {feeds.length === 0 ? (
                <div className="lg:col-span-12">
                  <div className="rounded-3xl bg-white/5 border border-white/10 p-12 text-center space-y-8 relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-500 to-transparent" />
                    <div className="max-w-2xl mx-auto space-y-6">
                      <div className="w-20 h-20 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center mx-auto shadow-2xl shadow-indigo-500/20">
                        <Shield className="w-10 h-10 text-indigo-400" />
                      </div>
                      <div className="space-y-2">
                        <h2 className="text-3xl font-black text-white uppercase tracking-tight">Sentinel AI Core</h2>
                        <p className="text-slate-400 text-sm leading-relaxed">
                          Advanced multi-feed surveillance intelligence. Upload video feeds or activate live monitoring to begin real-time threat assessment and automated response protocols.
                        </p>
                      </div>
                      <div className="grid grid-cols-3 gap-4 pt-4">
                        <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-2">
                          <Zap className="w-5 h-5 text-amber-400 mx-auto" />
                          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Real-time</span>
                        </div>
                        <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-2">
                          <Eye className="w-5 h-5 text-indigo-400 mx-auto" />
                          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Multi-feed</span>
                        </div>
                        <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-2">
                          <Bell className="w-5 h-5 text-rose-400 mx-auto" />
                          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Automated</span>
                        </div>
                      </div>
                      <div className="pt-8">
                        <div {...getRootProps()} className="group cursor-pointer">
                          <input {...getInputProps()} />
                          <div className="inline-flex items-center gap-3 px-8 py-4 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white font-black uppercase tracking-widest transition-all shadow-xl shadow-indigo-600/30 group-hover:scale-105 active:scale-95">
                            <Upload className="w-5 h-5" />
                            Initialize First Feed
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <>
                  <div className="lg:col-span-8 space-y-6">
                <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                  <div className="flex items-center gap-4">
                    <h2 className="text-sm font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
                      <Video className="w-4 h-4" /> Surveillance Grid
                    </h2>
                    <button onClick={() => setShowHeatmap(!showHeatmap)} className={cn("px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest border transition-all", showHeatmap ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-400" : "bg-white/5 border-white/10 text-slate-500")}>
                      Heatmap: {showHeatmap ? 'ON' : 'OFF'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <AnimatePresence mode="popLayout">
                    {feeds.map((feed) => (
                      <motion.div key={feed.id} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="group relative aspect-video rounded-xl bg-black border border-white/5 overflow-hidden shadow-lg hover:border-indigo-500/30 transition-all">
                        <video src={feed.url} className="w-full h-full object-cover" muted loop autoPlay />
                        {feed.isAnalyzing && <div className="scan-line" />}
                        {showHeatmap && feed.analysis && (
                          <div className="absolute inset-0 pointer-events-none">
                            {feed.analysis.events.map((event, eIdx) => (
                              <div key={eIdx} className="absolute w-24 h-24 -translate-x-1/2 -translate-y-1/2 rounded-full blur-2xl" style={{ left: `${event.spatial_coordinates.x}%`, top: `${event.spatial_coordinates.y}%`, background: event.classification === 'CRITICAL' ? 'radial-gradient(circle, rgba(244,63,94,0.6) 0%, transparent 70%)' : 'radial-gradient(circle, rgba(251,191,36,0.5) 0%, transparent 70%)' }} />
                            ))}
                          </div>
                        )}
                        <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-2">
                          <button onClick={() => removeFeed(feed.id)} className="p-2 rounded-full bg-rose-500 text-white shadow-lg hover:bg-rose-400 transition-colors"><X className="w-4 h-4" /></button>
                          {!feed.analysis && !feed.error && <button onClick={() => analyzeFeed(feed.id)} className="px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-[10px] font-bold uppercase tracking-widest shadow-lg hover:bg-indigo-500 transition-colors">ANALYZE</button>}
                          {feed.error && <button onClick={() => analyzeFeed(feed.id)} className="px-3 py-1.5 rounded-lg bg-amber-600 text-white text-[10px] font-bold uppercase tracking-widest shadow-lg hover:bg-amber-500 transition-colors flex items-center gap-1"><RefreshCw className="w-3 h-3" /> RETRY</button>}
                        </div>
                        {feed.isAnalyzing && <div className="absolute inset-0 bg-black/60 flex flex-col items-center justify-center gap-2 backdrop-blur-sm"><Loader2 className="w-6 h-6 text-indigo-500 animate-spin" /><span className="text-[10px] font-bold text-indigo-400 uppercase tracking-widest">ANALYZING...</span></div>}
                        {feed.error && !feed.isAnalyzing && <div className="absolute inset-0 bg-rose-500/20 flex flex-col items-center justify-center gap-2 backdrop-blur-sm p-4 text-center"><AlertTriangle className="w-6 h-6 text-rose-500" /><span className="text-[10px] font-bold text-rose-400 uppercase tracking-widest leading-tight">{feed.error}</span></div>}
                      </motion.div>
                    ))}
                    <div {...getRootProps()} className="aspect-video rounded-xl border-2 border-dashed border-white/10 flex flex-col items-center justify-center cursor-pointer hover:bg-white/5">
                      <input {...getInputProps()} />
                      <Upload className="w-8 h-8 text-slate-600 mb-2" />
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Drop Feed</p>
                    </div>
                  </AnimatePresence>
                </div>
              </div>

              <div className="lg:col-span-4 space-y-6">
                <div className="rounded-2xl bg-white/5 border border-white/10 p-6 h-full overflow-y-auto max-h-[calc(100vh-160px)] custom-scrollbar">
                  <div className="flex flex-col gap-4 mb-6">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Eye className="w-5 h-5 text-indigo-400" />
                        <h2 className="font-bold text-white uppercase tracking-wider text-sm">Intelligence Hub</h2>
                      </div>
                      <div className="flex items-center gap-2">
                        {['CRITICAL', 'SUSPICIOUS', 'BENIGN'].map(level => (
                          <button
                            key={level}
                            onClick={() => {
                              setFilterThreatLevels(prev => 
                                prev.includes(level) 
                                  ? prev.filter(l => l !== level) 
                                  : [...prev, level]
                              );
                            }}
                            className={cn(
                              "w-2 h-2 rounded-full transition-all",
                              filterThreatLevels.includes(level) 
                                ? level === 'CRITICAL' ? "bg-rose-500 shadow-[0_0_5px_#f43f5e]" : level === 'SUSPICIOUS' ? "bg-amber-500 shadow-[0_0_5px_#f59e0b]" : "bg-emerald-500 shadow-[0_0_5px_#10b981]"
                                : "bg-white/10"
                            )}
                            title={`Toggle ${level} alerts`}
                          />
                        ))}
                      </div>
                    </div>
                    <div className="relative group">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 group-focus-within:text-indigo-400 transition-colors" />
                      <input 
                        type="text"
                        value={eventSearch}
                        onChange={(e) => setEventSearch(e.target.value)}
                        placeholder="Search events..."
                        className="w-full pl-9 pr-4 py-2 bg-black/40 border border-white/10 rounded-xl text-[10px] text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all uppercase tracking-widest font-bold"
                      />
                    </div>
                  </div>
                  <div className="space-y-6">
                    {feeds.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-20 text-center">
                        <div className="w-12 h-12 rounded-full bg-white/5 flex items-center justify-center mb-4">
                          <Video className="w-6 h-6 text-slate-600" />
                        </div>
                        <p className="text-xs text-slate-500 max-w-[200px] uppercase tracking-widest leading-relaxed">
                          Awaiting surveillance input for core assessment.
                        </p>
                      </div>
                    ) : (
                      feeds.map((feed) => {
                        if (!feed.analysis) return null;
                        const filteredEvents = feed.analysis.events.filter(e => 
                          filterThreatLevels.includes(e.classification) &&
                          ((e.soc_justification?.toLowerCase() || "").includes(eventSearch.toLowerCase()) ||
                           e.subjects_tracked.some(subject => (subject.description?.toLowerCase() || "").includes(eventSearch.toLowerCase())))
                        );
                        
                        if (filteredEvents.length === 0) return null;

                        return (
                                    <div key={feed.id} className="space-y-4">
                                      <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/5 border border-white/5">
                                        <div className="flex items-center gap-2">
                                          <Camera className="w-3.5 h-3.5 text-indigo-400" />
                                          <span className="text-[10px] font-bold text-white">{feed.cameraId}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                          <span className={cn(
                                            "text-[9px] font-bold px-1.5 py-0.5 rounded",
                                            feed.analysis.analysis_status === 'SUCCESS' ? "bg-emerald-500/20 text-emerald-400" : "bg-slate-500/20 text-slate-400"
                                          )}>
                                            {feed.analysis.analysis_status}
                                          </span>
                                          <button 
                                            onClick={() => removeFeed(feed.id)}
                                            className="p-1 rounded hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 transition-colors"
                                            title="Remove Feed"
                                          >
                                            <X className="w-3 h-3" />
                                          </button>
                                        </div>
                                      </div>

                                      <div className="space-y-4">
                                        {filteredEvents.map((event, idx) => {
                                          const eventId = `${feed.id}-${idx}`;
                                          const isExpanded = expandedEventId === eventId;

                                          return (
                                            <motion.div 
                                              key={idx}
                                              layout
                                              initial={{ opacity: 0, y: 10 }}
                                              animate={{ opacity: 1, y: 0 }}
                                              onClick={() => setExpandedEventId(isExpanded ? null : eventId)}
                                              className={cn(
                                                "space-y-4 p-4 rounded-xl bg-white/5 border border-white/5 relative overflow-hidden cursor-pointer transition-all hover:bg-white/10",
                                                isExpanded && "ring-2 ring-indigo-500/50 bg-white/10"
                                              )}
                                            >
                                              <div className={cn("absolute top-0 left-0 w-1 h-full", 
                                                event.classification === 'BENIGN' ? "bg-emerald-500" : 
                                                event.classification === 'SUSPICIOUS' ? "bg-amber-500" : "bg-rose-500"
                                              )} />
                                              
                                              <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-2">
                                                  <div className={cn("px-2 py-0.5 rounded text-[9px] font-bold border shadow-sm", getStatusColor(event.classification))}>
                                                    {event.classification}
                                                  </div>
                                                  <span className="text-[9px] font-mono text-slate-500 flex items-center gap-1">
                                                    <Clock className="w-2.5 h-2.5" />
                                                    {event.timestamps.event_onset}
                                                  </span>
                                                </div>
                                                <div className={cn("text-base font-black glow-text", getThreatColor(event.threat_level).split(' ')[0])}>
                                                  {event.threat_level}/10
                                                </div>
                                              </div>

                                              <div className="space-y-3">
                                                <div className="space-y-1.5">
                                                  <div className="space-y-1">
                                                    {event.subjects_tracked.map((subject, sIdx) => (
                                                      <div key={sIdx} className="flex items-center gap-2 p-1.5 rounded bg-black/40 border border-white/5">
                                                        {subject.type === 'PERSON' ? <User className="w-3 h-3 text-indigo-400" /> : <Car className="w-3 h-3 text-indigo-400" />}
                                                        <p className={cn("text-[10px] text-slate-300 truncate flex-1", isExpanded && "whitespace-normal truncate-none")}>
                                                          {subject.description}
                                                        </p>
                                                        {subject.concealment_detected && (
                                                          <AlertCircle className="w-3 h-3 text-rose-400" />
                                                        )}
                                                      </div>
                                                    ))}
                                                  </div>
                                                </div>

                                                <p className={cn("text-[10px] text-slate-500 leading-relaxed italic", isExpanded && "text-xs text-slate-400")}>
                                                  "{event.soc_justification}"
                                                </p>

                                                {isExpanded && (
                                                  <motion.div 
                                                    initial={{ opacity: 0, height: 0 }}
                                                    animate={{ opacity: 1, height: 'auto' }}
                                                    className="pt-4 space-y-4 border-t border-white/5"
                                                  >
                                                    <div className="grid grid-cols-2 gap-4">
                                                      <div className="space-y-1">
                                                        <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Event Timeframe</span>
                                                        <p className="text-[11px] text-white font-mono">{event.timestamps.event_onset} - {event.timestamps.event_conclusion}</p>
                                                      </div>
                                                      <div className="space-y-1 text-right">
                                                        <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Confidence Score</span>
                                                        <p className="text-[11px] text-indigo-400 font-mono">{(event.confidence_score * 100).toFixed(2)}%</p>
                                                      </div>
                                                    </div>
                                                    <div className="space-y-1">
                                                      <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Spatial Context</span>
                                                      <p className="text-[11px] text-slate-300">
                                                        Detected at {event.spatial_coordinates?.x.toFixed(1)}% X, {event.spatial_coordinates?.y.toFixed(1)}% Y in frame.
                                                      </p>
                                                    </div>
                                                  </motion.div>
                                                )}
                                              </div>
                                            </motion.div>
                                          );
                                        })}
                                      </div>
                                    </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
              <div className="lg:col-span-12">
                <div className="rounded-2xl bg-white/5 border border-white/10 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Activity className="w-5 h-5 text-indigo-400" />
                      <h2 className="font-bold text-white uppercase tracking-wider text-sm">System Logs</h2>
                    </div>
                    <button onClick={() => setSystemLogs([])} className="text-[10px] uppercase text-slate-500 hover:text-rose-400">Clear Logs</button>
                  </div>
                  <div className="space-y-2 max-h-[200px] overflow-y-auto custom-scrollbar pr-4 font-mono">
                    {systemLogs.length === 0 ? (
                      <p className="text-[10px] text-slate-600 uppercase tracking-widest text-center py-4">No logs recorded.</p>
                    ) : (
                      systemLogs.map(log => (
                        <div key={log.id} className="flex gap-4 text-[11px] py-1 border-b border-white/5 last:border-0">
                          <span className="text-slate-500 shrink-0">[{log.time}]</span>
                          <span className={cn(
                            "font-bold shrink-0 w-12",
                            log.type === 'INFO' ? "text-indigo-400" : 
                            log.type === 'WARN' ? "text-amber-400" : "text-rose-400"
                          )}>{log.type}</span>
                          <span className="text-slate-300">{log.msg}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </>
        ) : (
          // --- LIVE MODE UI ---
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            <div className="lg:col-span-7 space-y-6">
              <div className="relative aspect-video rounded-2xl bg-black border border-white/5 overflow-hidden group shadow-2xl">
                {!stream ? (
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <div className="w-16 h-16 rounded-full bg-indigo-500/10 flex items-center justify-center mb-4"><Camera className="w-8 h-8 text-indigo-400" /></div>
                    <p className="text-lg font-medium text-slate-300">Camera Offline</p>
                    <button onClick={startLiveMode} className="mt-6 px-6 py-2.5 rounded-xl bg-indigo-600 text-white font-bold text-sm uppercase tracking-widest">Connect Camera</button>
                  </div>
                ) : (
                  <>
                    <video ref={videoRef} className="w-full h-full object-contain" autoPlay muted playsInline />
                    <div className="absolute top-4 left-4 flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/20 border border-rose-500/30 backdrop-blur-md shadow-lg z-10">
                      <div className="w-2 h-2 rounded-full bg-rose-500 animate-pulse shadow-[0_0_8px_#f43f5e]" />
                      <span className="text-[10px] font-bold text-rose-400 uppercase tracking-widest">Live Feed</span>
                    </div>
                    {isMonitoring && <div className="scan-line z-10" />}
                    {isMonitoring && (
                      <div className="absolute bottom-4 left-4 flex items-center gap-2 px-3 py-1.5 rounded-full bg-black/60 border border-white/10 backdrop-blur-md z-10">
                        <RefreshCw className="w-3 h-3 text-indigo-400 animate-spin" />
                        <span className="text-[9px] font-bold text-indigo-400 uppercase tracking-widest">AI Monitoring Active</span>
                      </div>
                    )}
                    {liveAnalysis && liveAnalysis.analysis.subjects.map((subject, sIdx) => (
                      <div 
                        key={sIdx} 
                        className={cn(
                          "absolute border-2 transition-all duration-300",
                          subject.is_primary ? "border-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.5)]" : "border-indigo-500/50"
                        )}
                        style={{
                          top: `${subject.box_2d[0] / 10}%`,
                          left: `${subject.box_2d[1] / 10}%`,
                          width: `${(subject.box_2d[3] - subject.box_2d[1]) / 10}%`,
                          height: `${(subject.box_2d[2] - subject.box_2d[0]) / 10}%`
                        }}
                      >
                        {subject.is_primary && <div className="pulse-ring" />}
                        <div className={cn(
                          "absolute -top-6 left-0 px-2 py-0.5 rounded text-[8px] font-bold uppercase tracking-widest whitespace-nowrap",
                          subject.is_primary ? "bg-rose-500 text-white" : "bg-indigo-500/80 text-white"
                        )}>
                          {subject.label} {subject.is_primary && "• PRIMARY THREAT"}
                        </div>
                      </div>
                    ))}
                    {isAudioEnabled && (
                      <div className="absolute top-4 right-4 flex items-center gap-3 px-4 py-2 rounded-full bg-black/60 border border-white/10 backdrop-blur-md">
                        <div className="flex items-center gap-[2px] h-6 w-32">
                          {audioFrequencies.map((freq, i) => {
                            // Color based on frequency band
                            let colorClass = "bg-emerald-400"; // Bass
                            if (i > 10 && i <= 22) colorClass = "bg-indigo-400"; // Mid
                            if (i > 22) colorClass = "bg-rose-400"; // Treble
                            
                            return (
                              <motion.div 
                                key={i} 
                                animate={{ 
                                  height: isMonitoring ? `${Math.max(15, freq * 100)}%` : "15%",
                                  opacity: 0.3 + (freq * 0.7)
                                }} 
                                className={cn("w-[2px] rounded-full transition-colors", colorClass)} 
                                style={{
                                  boxShadow: freq > 0.5 ? `0 0 8px ${i > 22 ? '#fb7185' : i > 10 ? '#818cf8' : '#34d399'}` : 'none'
                                }}
                              />
                            );
                          })}
                        </div>
                        <div className="flex flex-col items-center">
                          <Volume2 className="w-3 h-3 text-indigo-400" />
                          <span className="text-[8px] font-bold text-slate-500 uppercase mt-0.5">Live</span>
                        </div>
                      </div>
                    )}
                    {liveAnalysis?.analysis.subjects.map((subject, i) => (
                      <div key={i} className={cn("absolute border-2 pointer-events-none z-20", subject.is_primary ? "border-rose-500" : "border-amber-400/60")} style={{ top: `${subject.box_2d[0] / 10}%`, left: `${subject.box_2d[1] / 10}%`, height: `${(subject.box_2d[2] - subject.box_2d[0]) / 10}%`, width: `${(subject.box_2d[3] - subject.box_2d[1]) / 10}%` }}>
                        <div className={cn("absolute top-0 left-0 -translate-y-full text-white text-[8px] px-1 font-bold uppercase", subject.is_primary ? "bg-rose-500" : "bg-amber-400/60")}>{subject.label}</div>
                      </div>
                    ))}
                  </>
                )}
              </div>

              {stream && (
                <div className="grid grid-cols-2 gap-4">
                  <button onClick={toggleMonitoring} className={cn("py-4 rounded-xl font-bold text-sm uppercase tracking-widest transition-all flex items-center justify-center gap-2", isMonitoring ? "bg-rose-600 text-white" : "bg-emerald-600 text-white")}>
                    {isMonitoring ? <MonitorOff className="w-4 h-4" /> : <Monitor className="w-4 h-4" />}
                    {isMonitoring ? "Stop Monitoring" : "Start Monitoring"}
                  </button>
                  <button onClick={toggleAudio} className={cn("py-4 rounded-xl font-bold text-sm uppercase tracking-widest transition-all flex items-center justify-center gap-2", isAudioEnabled ? "bg-indigo-600 text-white" : "bg-white/5 border border-white/10 text-slate-400")}>
                    {isAudioEnabled ? <Mic className="w-4 h-4" /> : <MicOff className="w-4 h-4" />}
                    {isAudioEnabled ? "Mic Active" : "Enable Mic"}
                  </button>
                </div>
              )}

              <div className="rounded-2xl bg-white/5 border border-white/10 p-6">
                <div className="flex flex-col gap-4 mb-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <History className="w-5 h-5 text-amber-400" />
                      <h2 className="font-bold text-white uppercase tracking-wider text-sm">Threat Timeline</h2>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => setThreatEvents([])} className="p-1.5 rounded-lg hover:bg-rose-500/10 text-slate-500 hover:text-rose-400 transition-colors" title="Clear Timeline">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  <div className="relative group">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 group-focus-within:text-indigo-400 transition-colors" />
                    <input 
                      type="text"
                      value={eventSearch}
                      onChange={(e) => setEventSearch(e.target.value)}
                      placeholder="Search timeline..."
                      className="w-full pl-9 pr-4 py-2 bg-black/40 border border-white/10 rounded-xl text-[10px] text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all uppercase tracking-widest font-bold"
                    />
                  </div>
                </div>
                <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                  {threatEvents.filter(event => 
                    (event.analysis.analysis.primary_activity?.toLowerCase() || "").includes(eventSearch.toLowerCase()) ||
                    event.analysis.analysis.subjects_detected?.some(subject => (subject?.toLowerCase() || "").includes(eventSearch.toLowerCase()))
                  ).length === 0 ? (
                    <div className="py-12 text-center space-y-2 opacity-30">
                      <History className="w-8 h-8 mx-auto text-slate-500" />
                      <p className="text-[10px] font-bold uppercase tracking-widest">No matching events</p>
                    </div>
                  ) : (
                    threatEvents.filter(event => 
                      (event.analysis.analysis.primary_activity?.toLowerCase() || "").includes(eventSearch.toLowerCase()) ||
                      event.analysis.analysis.subjects_detected?.some(subject => (subject?.toLowerCase() || "").includes(eventSearch.toLowerCase()))
                    ).map(event => (
                      <motion.div 
                        key={event.id} 
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        onClick={() => setSelectedEvent(event)} 
                        className="group flex gap-4 p-3 rounded-xl bg-white/5 border border-white/5 hover:border-rose-500/30 hover:bg-white/10 cursor-pointer transition-all relative overflow-hidden"
                      >
                        <div className={cn("absolute top-0 left-0 w-1 h-full", 
                          event.analysis.threat_assessment.level >= 8 ? "bg-rose-500" : "bg-amber-500"
                        )} />
                        <div className="w-20 aspect-video rounded-lg overflow-hidden border border-white/10 shrink-0">
                          <img src={event.snapshot} className="w-full h-full object-cover opacity-60 group-hover:opacity-100 transition-opacity" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex justify-between items-center mb-1">
                            <span className={cn("text-[9px] font-black px-1.5 py-0.5 rounded uppercase tracking-tighter", 
                              event.analysis.threat_assessment.level >= 8 ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                            )}>LVL {event.analysis.threat_assessment.level}</span>
                            <span className="text-[9px] font-mono text-slate-500">{event.timestamp.toLocaleTimeString([], { hour12: false })}</span>
                          </div>
                          <p className="text-[11px] text-slate-200 font-bold truncate group-hover:text-white transition-colors">{event.analysis.analysis.primary_activity}</p>
                        </div>
                      </motion.div>
                    ))
                  )}
                </div>
              </div>
            </div>

            <div className="lg:col-span-5 space-y-6">
              <div className="rounded-2xl bg-white/5 border border-white/10 p-6 h-full overflow-y-auto max-h-[calc(100vh-160px)] custom-scrollbar">
                <div className="flex items-center justify-between mb-8">
                  <div className="flex items-center gap-2">
                    <Eye className="w-5 h-5 text-indigo-400" />
                    <h2 className="font-bold text-white uppercase tracking-wider text-sm">Live Analysis</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
                    <span className="text-[10px] font-mono text-slate-500">{lastAnalysisTime?.toLocaleTimeString([], { hour12: false }) || '--:--:--'}</span>
                  </div>
                </div>

                {!liveAnalysis ? (
                  <div className="flex flex-col items-center justify-center py-20 text-center space-y-4 opacity-30">
                    <div className="w-16 h-16 rounded-full bg-white/5 border border-white/5 flex items-center justify-center">
                      <Activity className="w-8 h-8 text-slate-500" />
                    </div>
                    <p className="text-[10px] font-bold uppercase tracking-widest">Awaiting Signal</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 rounded-xl bg-white/5 border border-white/5">
                        <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest block mb-2">Status</span>
                        <div className={cn("inline-block px-2 py-0.5 rounded text-[10px] font-bold border", getStatusColor(liveAnalysis.threat_assessment.status))}>
                          {liveAnalysis.threat_assessment.status}
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/5 border border-white/5 text-right">
                        <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest block mb-2">Threat Level</span>
                        <div className={cn("text-2xl font-black glow-text", getThreatColor(liveAnalysis.threat_assessment.level).split(' ')[0])}>
                          {liveAnalysis.threat_assessment.level}/10
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="p-4 rounded-xl bg-white/5 border border-white/5">
                        <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest block mb-2">Primary Activity</span>
                        <p className="text-sm text-white font-medium leading-relaxed">{liveAnalysis.analysis.primary_activity}</p>
                      </div>

                      {liveAnalysis.analysis.audio_analysis && (
                        <div className="p-4 rounded-xl bg-indigo-500/5 border border-indigo-500/10 space-y-3">
                          <div className="flex items-center gap-2">
                            <Volume2 className="w-4 h-4 text-indigo-400" />
                            <span className="text-[9px] font-bold text-indigo-400 uppercase tracking-widest">Audio Intelligence</span>
                          </div>
                          <p className="text-[11px] text-slate-300 italic leading-relaxed">"{liveAnalysis.analysis.audio_analysis.description}"</p>
                          <div className="flex flex-wrap gap-2">
                            {liveAnalysis.analysis.audio_analysis.detected_sounds.map((sound, sIdx) => (
                              <span key={sIdx} className="text-[8px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 uppercase font-bold">
                                {sound}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="space-y-2">
                        <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Recommendation</span>
                        <div className="p-4 rounded-xl bg-white/5 border border-white/5">
                          <div className="flex items-center gap-2 mb-2">
                            <ShieldAlert className="w-4 h-4 text-rose-400" />
                            <p className="text-rose-400 font-black text-sm uppercase tracking-tight">{liveAnalysis.recommendation.action.replace('_', ' ')}</p>
                          </div>
                          <p className="text-slate-400 text-xs italic leading-relaxed">"{liveAnalysis.recommendation.justification}"</p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </main>

      <canvas ref={canvasRef} className="hidden" />

      {/* Threat Detail Modal */}
      <AnimatePresence>
        {selectedEvent && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedEvent(null)} className="absolute inset-0 bg-black/90 backdrop-blur-md" />
            <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.9 }} className="relative w-full max-w-5xl bg-[#0f0f12] border border-white/10 rounded-3xl overflow-hidden shadow-2xl flex flex-col lg:flex-row max-h-[90vh]">
              <button onClick={() => setSelectedEvent(null)} className="absolute top-4 right-4 z-50 p-2 rounded-full bg-black/60 text-white hover:bg-rose-500"><X className="w-5 h-5" /></button>
              <div className="lg:w-2/3 bg-black relative flex items-center justify-center min-h-[300px]">
                <img src={selectedEvent.snapshot} className="w-full h-full object-contain" />
                {selectedEvent.analysis.analysis.subjects.map((subject, i) => (
                  <div key={i} className={cn("absolute border-2 pointer-events-none", subject.is_primary ? "border-rose-500" : "border-amber-400/60")} style={{ top: `${subject.box_2d[0] / 10}%`, left: `${subject.box_2d[1] / 10}%`, height: `${(subject.box_2d[2] - subject.box_2d[0]) / 10}%`, width: `${(subject.box_2d[3] - subject.box_2d[1]) / 10}%` }} />
                ))}
              </div>
              <div className="lg:w-1/3 p-8 overflow-y-auto border-l border-white/10 space-y-6">
                <h3 className="text-2xl font-black text-white uppercase tracking-tight">Event Analysis</h3>
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-white/5 border border-white/5">
                    <div className="flex justify-between items-end mb-2">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Threat Intensity</span>
                      <span className={cn("text-2xl font-black glow-text", getThreatColor(selectedEvent.analysis.threat_assessment.level).split(' ')[0])}>
                        {selectedEvent.analysis.threat_assessment.level}/10
                      </span>
                    </div>
                    <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${selectedEvent.analysis.threat_assessment.level * 10}%` }}
                        className={cn("h-full rounded-full", 
                          selectedEvent.analysis.threat_assessment.level <= 3 ? "bg-emerald-500" : 
                          selectedEvent.analysis.threat_assessment.level <= 7 ? "bg-amber-500" : "bg-rose-500"
                        )}
                        style={{ boxShadow: `0 0 10px ${selectedEvent.analysis.threat_assessment.level <= 3 ? '#10b981' : selectedEvent.analysis.threat_assessment.level <= 7 ? '#f59e0b' : '#f43f5e'}` }}
                      />
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-white/5 border border-white/5"><span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Primary Activity</span><p className="text-sm text-slate-200 mt-1 leading-relaxed">{selectedEvent.analysis.analysis.primary_activity}</p></div>
                  <div className="p-4 rounded-xl bg-indigo-500/5 border border-indigo-500/10">
                    <div className="flex items-center gap-2 mb-2">
                      <ShieldAlert className="w-4 h-4 text-indigo-400" />
                      <span className="text-[10px] font-bold text-indigo-400 uppercase tracking-widest">Recommendation</span>
                    </div>
                    <p className="text-white font-bold mt-1">{selectedEvent.analysis.recommendation.action}</p>
                    <p className="text-xs text-slate-400 italic mt-2 leading-relaxed">"{selectedEvent.analysis.recommendation.justification}"</p>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Background Accents */}
      <div className="fixed top-0 left-0 w-full h-full pointer-events-none overflow-hidden -z-10">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-indigo-600/10 blur-[120px] rounded-full" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-600/10 blur-[120px] rounded-full" />
      </div>

      {/* Success Popup */}
      <AnimatePresence>
        {showSuccessPopup && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="fixed inset-0 flex items-center justify-center z-50 pointer-events-none"
          >
            <motion.div
              initial={{ y: 20 }}
              animate={{ y: 0 }}
              exit={{ y: 20 }}
              className="bg-slate-800/95 backdrop-blur-xl border border-slate-700/50 rounded-xl p-6 shadow-2xl shadow-slate-900/50 pointer-events-auto"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white mb-1">Success</h3>
                  <p className="text-slate-300 text-sm">Email ID saved successfully</p>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Email Popup */}
      <AnimatePresence>
        {emailPopupMessage && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="fixed inset-0 flex items-center justify-center z-50 pointer-events-none"
          >
            <motion.div
              initial={{ y: 20 }}
              animate={{ y: 0 }}
              exit={{ y: 20 }}
              className="bg-slate-800/95 backdrop-blur-xl border border-emerald-500/30 rounded-xl p-6 shadow-2xl shadow-slate-900/50 pointer-events-auto"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center">
                  <Mail className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white mb-1">Email Notification</h3>
                  <p className="text-slate-300 text-sm">{emailPopupMessage}</p>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
