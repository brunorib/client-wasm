pub const CONCAT: &str = "|";

#[derive(Serialize, Deserialize, Clone)]
pub struct AnswerInfo {
    pub blinding: String,
    pub amount: String,
    pub id: String
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitInfoPayload {
    pub commits: Vec<String>,
    pub answers: Vec<AnswerInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitResponse {
    pub status: String,
    pub message: String,
    pub user_id: u32,
    pub to_exclude_answers: usize
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlindSignature {
    pub blind_signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Token {
    pub signature: String,
    pub amount: String,
    pub id: String
}