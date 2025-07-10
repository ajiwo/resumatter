package types

// TailorResumeInput represents the input for tailoring a resume
type TailorResumeInput struct {
	BaseResume     string `json:"baseResume"`
	JobDescription string `json:"jobDescription"`
}

// ATSAnalysis represents the ATS scoring and analysis
type ATSAnalysis struct {
	Score      int    `json:"score"`
	Strengths  string `json:"strengths"`
	Weaknesses string `json:"weaknesses"`
}

// JobPostingAnalysis represents the analysis of the job posting
type JobPostingAnalysis struct {
	Clarity     string `json:"clarity"`
	Inclusivity string `json:"inclusivity"`
	Quality     string `json:"quality"`
}

// TailorResumeOutput represents the output from tailoring a resume
type TailorResumeOutput struct {
	TailoredResume     string             `json:"tailoredResume"`
	ATSAnalysis        ATSAnalysis        `json:"atsAnalysis"`
	JobPostingAnalysis JobPostingAnalysis `json:"jobPostingAnalysis"`
}

// EvaluateResumeInput represents the input for evaluating a resume
type EvaluateResumeInput struct {
	BaseResume     string `json:"baseResume"`
	TailoredResume string `json:"tailoredResume"`
}

// EvaluationFinding represents a specific issue found in the evaluation
type EvaluationFinding struct {
	Type        string `json:"type"` // "Overclaim", "Invention", or "Incorrect Linking"
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

// EvaluateResumeOutput represents the output from evaluating a resume
type EvaluateResumeOutput struct {
	Summary  string              `json:"summary"`
	Findings []EvaluationFinding `json:"findings"`
}

// AnalyzeJobInput represents the input for analyzing a job description
type AnalyzeJobInput struct {
	JobDescription string `json:"jobDescription"`
}

// JobQualityScore represents a scored aspect of job quality
type JobQualityScore struct {
	Score        int      `json:"score"`        // 0-100 score
	Analysis     string   `json:"analysis"`     // Detailed analysis
	Improvements []string `json:"improvements"` // Specific improvement suggestions
}

// InclusivityAnalysis represents inclusivity assessment with specific feedback
type InclusivityAnalysis struct {
	Score        int      `json:"score"`        // 0-100 score
	Analysis     string   `json:"analysis"`     // Overall assessment
	FlaggedTerms []string `json:"flaggedTerms"` // Potentially problematic terms
	Suggestions  []string `json:"suggestions"`  // Specific improvement suggestions
}

// CandidateAttraction represents how well the job attracts candidates
type CandidateAttraction struct {
	Score      int      `json:"score"`      // 0-100 score
	Strengths  []string `json:"strengths"`  // What attracts candidates
	Weaknesses []string `json:"weaknesses"` // What might deter candidates
}

// MarketCompetitiveness represents market analysis of the job posting
type MarketCompetitiveness struct {
	SalaryTransparency  string `json:"salaryTransparency"`  // Assessment of salary disclosure
	RequirementsRealism string `json:"requirementsRealism"` // Whether requirements are realistic
	IndustryAlignment   string `json:"industryAlignment"`   // How well it aligns with industry standards
}

// AnalyzeJobOutput represents the comprehensive output from job analysis
type AnalyzeJobOutput struct {
	JobQualityScore       int                   `json:"jobQualityScore"`       // Overall score 0-100
	Clarity               JobQualityScore       `json:"clarity"`               // Clarity assessment
	Inclusivity           InclusivityAnalysis   `json:"inclusivity"`           // Inclusivity analysis
	CandidateAttraction   CandidateAttraction   `json:"candidateAttraction"`   // Attraction analysis
	MarketCompetitiveness MarketCompetitiveness `json:"marketCompetitiveness"` // Market analysis
	Recommendations       []string              `json:"recommendations"`       // Top-level recommendations
}
