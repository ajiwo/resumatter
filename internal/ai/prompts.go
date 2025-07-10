package ai

// SystemPrompts contains all system-level instructions for AI interactions
type SystemPrompts struct {
	TailorResume   string
	EvaluateResume string
	AnalyzeJob     string
}

// UserPrompts contains user-level prompts with placeholders for dynamic content
type UserPrompts struct {
	TailorResume   string
	EvaluateResume string
	AnalyzeJob     string
}

// DefaultSystemPrompts provides the default system instructions
var DefaultSystemPrompts = SystemPrompts{
	TailorResume: `You are an expert resume writer and HR analyst with a strict commitment to honesty and accuracy. Your core principles are:

- NEVER invent, exaggerate, or misattribute any skills or experiences
- Every piece of information must be directly traceable to the source material
- Maintain professional integrity while optimizing for relevance
- Provide honest, data-driven analysis

Your expertise includes:
- Resume optimization and tailoring
- ATS (Applicant Tracking System) analysis
- Job posting quality assessment
- HR best practices and industry standards`,

	EvaluateResume: `You are an expert resume reviewer and integrity analyst with a focus on accuracy and authenticity. Your role is to:

- Identify discrepancies between original and tailored content
- Detect fabrications, exaggerations, and misattributions
- Ensure factual consistency across documents
- Provide detailed evidence-based findings

You specialize in detecting three types of integrity issues:
1. Overclaims: Exaggerated or embellished content
2. Inventions: Completely fabricated information
3. Incorrect Linking: Misattributed skills or achievements`,

	AnalyzeJob: `You are an expert HR consultant and recruitment specialist with deep knowledge of:

- Job posting optimization and best practices
- Inclusive hiring and bias detection
- Candidate attraction and market competitiveness
- Employment law and compliance requirements
- Industry standards and benchmarking

Your role is to analyze job descriptions comprehensively and provide actionable insights to help organizations:
1 Attract qualified, diverse candidates
2 Improve job posting effectiveness
3 Ensure inclusive and bias-free language
4 Optimize for applicant tracking systems and job boards
5 Align with current market standards and expectations`,
}

// DefaultUserPrompts provides the default user prompt templates
var DefaultUserPrompts = UserPrompts{
	TailorResume: `Please perform a comprehensive analysis based on the provided resume and job description.

**Tasks:**

1. **Tailor Resume**:
   Generate a tailored resume that highlights the most relevant skills and experience *explicitly present in the base resume*.
   When incorporating keywords from the job description, only do so if the corresponding skill or experience actually exists in the base resume.

2. **ATS Analysis**:
   Simulate an Applicant Tracking System (ATS) score for the **base resume** against the job description.
   Provide a score from 0 to 100, and detail the resume's strengths and weaknesses for this specific role.

3. **Job Posting Analysis**:
   Analyze the provided job posting for its quality. Evaluate its:
   - Clarity (is it easy to understand?)
   - Inclusivity (does it use welcoming and unbiased language?)
   - Overall quality (is it a well-written, appealing job post?)

**Base Resume:**
-----
%s
-----

**Job Description:**
-----
%s
-----`,

	EvaluateResume: `Please analyze the "Tailored Resume" and compare it against the "Base Resume" to identify any potential fabrications or exaggerations.

**Focus on these three specific types of issues:**

1. **Overclaim**: Identify any skills, responsibilities, or achievements that have been exaggerated or embellished in the tailored resume compared to what is stated in the base resume.

2. **Invention**: Find any skills, metrics, KPIs, or achievements in the tailored resume that are completely absent from the base resume.

3. **Incorrect Linking**: Detect instances where a skill or accomplishment from one part of the base resume has been incorrectly attributed to a different job or project in the tailored resume.

For each issue you find, create a "finding" with the type of issue, a detailed description, and the specific text from the tailored resume that constitutes the issue.
If no issues are found, state that clearly in the summary and provide an empty findings array.

**Base Resume:**
-----
%s
-----

**Tailored Resume:**
-----
%s
-----`,

	AnalyzeJob: `Please perform a comprehensive analysis of the provided job description to help optimize it for attracting qualified candidates and ensuring best practices.

**Analysis Areas:**

1. **Overall Job Quality Score** (0-100):
   Provide an overall assessment of the job posting quality.

2. **Clarity Assessment**:
   - Score (0-100) for how clear and understandable the job description is
   - Detailed analysis of structure, language, and comprehensibility
   - Specific improvements for better clarity

3. **Inclusivity Analysis**:
   - Score (0-100) for inclusive language and bias-free content
   - Overall assessment of inclusivity
   - Flag any potentially problematic terms or phrases
   - Provide specific suggestions for more inclusive language

4. **Candidate Attraction**:
   - Score (0-100) for how attractive this posting is to qualified candidates
   - List specific strengths that would attract candidates
   - Identify weaknesses that might deter good candidates

5. **Market Competitiveness**:
   - Assess salary transparency (good/fair/poor and why)
   - Evaluate if requirements are realistic for the role level
   - Determine how well it aligns with current industry standards

6. **Top Recommendations**:
   Provide 3-5 high-impact recommendations for improving this job posting.

**Job Description to Analyze:**
-----
%s
-----`,
}

// PromptConfig holds configuration for customizable prompts
type PromptConfig struct {
	SystemPrompts SystemPrompts `json:"systemPrompts"`
	UserPrompts   UserPrompts   `json:"userPrompts"`
}

// GetDefaultPromptConfig returns the default prompt configuration
func GetDefaultPromptConfig() PromptConfig {
	return PromptConfig{
		SystemPrompts: DefaultSystemPrompts,
		UserPrompts:   DefaultUserPrompts,
	}
}
