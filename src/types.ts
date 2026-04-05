export type RecommendedAction = 'IGNORE' | 'LOG' | 'DISPATCH_AUTHORITIES';
export type ThreatStatus = 'BENIGN' | 'SUSPICIOUS' | 'CRITICAL';
export type SubjectType = 'PERSON' | 'VEHICLE';

export interface SubjectTracked {
  type: SubjectType;
  description: string;
  concealment_detected: boolean;
}

export interface SecurityEvent {
  classification: ThreatStatus;
  threat_level: number;
  confidence_score: number;
  spatial_coordinates: { x: number; y: number };
  timestamps: {
    event_onset: string;
    event_conclusion: string;
  };
  subjects_tracked: SubjectTracked[];
  action_required: RecommendedAction;
  soc_justification: string;
}

export interface FileSecurityAnalysis {
  camera_id: string;
  analysis_status: 'SUCCESS' | 'NO_ANOMALY';
  events: SecurityEvent[];
}

export interface BoundingBox {
  box_2d: [number, number, number, number];
  label: string;
  is_primary: boolean;
  threat_contribution: string;
}

export interface LiveSecurityAnalysis {
  analysis: {
    subjects_detected: string[];
    primary_activity: string;
    is_authorized_behavior: boolean;
    confidence_score: number;
    subjects: BoundingBox[];
    audio_analysis?: {
      detected_sounds: string[];
      threat_level: number;
      description: string;
    };
  };
  threat_assessment: {
    level: number;
    indicators: string[];
    status: ThreatStatus;
  };
  recommendation: {
    action: RecommendedAction;
    justification: string;
  };
}

export interface ThreatEvent {
  id: string;
  timestamp: Date;
  snapshot: string;
  analysis: LiveSecurityAnalysis;
}
