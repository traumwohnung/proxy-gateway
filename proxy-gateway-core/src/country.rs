//! ISO 3166-1 alpha-2 country codes, shared across proxy sources.

/// ISO 3166-1 alpha-2 country codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Country {
    AD, AE, AF, AG, AL, AM, AO, AR, AT, AU, AZ,
    BA, BB, BD, BE, BF, BG, BH, BI, BJ, BN, BO, BR, BS, BT, BW, BY, BZ,
    CA, CD, CG, CH, CI, CL, CM, CN, CO, CR, CU, CV, CW, CY, CZ,
    DE, DJ, DK, DM, DO, DZ,
    EC, EE, EG, ES, ET,
    FI, FJ, FR,
    GA, GB, GD, GE, GF, GH, GM, GN, GP, GQ, GR, GT, GW, GY,
    HK, HN, HR, HT, HU,
    ID, IE, IL, IM, IN, IQ, IR, IS, IT,
    JE, JM, JO, JP,
    KE, KG, KH, KM, KR, KW, KY, KZ,
    LA, LB, LC, LK, LS, LT, LU, LV, LY,
    MA, MD, ME, MG, MK, ML, MM, MN, MO, MQ, MR, MT, MU, MV, MW, MX, MY, MZ,
    NA, NE, NG, NI, NL, NO, NP, NZ,
    OM,
    PA, PE, PG, PH, PK, PL, PR, PS, PT, PY,
    QA,
    RE, RO, RS, RU, RW,
    SA, SC, SE, SG, SI, SK, SL, SN, SO, SR, ST, SV, SX, SY,
    TG, TH, TJ, TM, TN, TR, TT, TW, TZ,
    UA, UG, US, UY, UZ,
    VC, VE, VI, VN,
    XK,
    YE, YT,
    ZA, ZM, ZW,
}

impl Country {
    /// The lowercase string used in the upstream proxy username (e.g. `"us"`, `"de"`).
    pub fn as_param_str(self) -> &'static str {
        match self {
            Self::AD => "ad", Self::AE => "ae", Self::AF => "af", Self::AG => "ag",
            Self::AL => "al", Self::AM => "am", Self::AO => "ao", Self::AR => "ar",
            Self::AT => "at", Self::AU => "au", Self::AZ => "az",
            Self::BA => "ba", Self::BB => "bb", Self::BD => "bd", Self::BE => "be",
            Self::BF => "bf", Self::BG => "bg", Self::BH => "bh", Self::BI => "bi",
            Self::BJ => "bj", Self::BN => "bn", Self::BO => "bo", Self::BR => "br",
            Self::BS => "bs", Self::BT => "bt", Self::BW => "bw", Self::BY => "by",
            Self::BZ => "bz",
            Self::CA => "ca", Self::CD => "cd", Self::CG => "cg", Self::CH => "ch",
            Self::CI => "ci", Self::CL => "cl", Self::CM => "cm", Self::CN => "cn",
            Self::CO => "co", Self::CR => "cr", Self::CU => "cu", Self::CV => "cv",
            Self::CW => "cw", Self::CY => "cy", Self::CZ => "cz",
            Self::DE => "de", Self::DJ => "dj", Self::DK => "dk", Self::DM => "dm",
            Self::DO => "do", Self::DZ => "dz",
            Self::EC => "ec", Self::EE => "ee", Self::EG => "eg", Self::ES => "es",
            Self::ET => "et",
            Self::FI => "fi", Self::FJ => "fj", Self::FR => "fr",
            Self::GA => "ga", Self::GB => "gb", Self::GD => "gd", Self::GE => "ge",
            Self::GF => "gf", Self::GH => "gh", Self::GM => "gm", Self::GN => "gn",
            Self::GP => "gp", Self::GQ => "gq", Self::GR => "gr", Self::GT => "gt",
            Self::GW => "gw", Self::GY => "gy",
            Self::HK => "hk", Self::HN => "hn", Self::HR => "hr", Self::HT => "ht",
            Self::HU => "hu",
            Self::ID => "id", Self::IE => "ie", Self::IL => "il", Self::IM => "im",
            Self::IN => "in", Self::IQ => "iq", Self::IR => "ir", Self::IS => "is",
            Self::IT => "it",
            Self::JE => "je", Self::JM => "jm", Self::JO => "jo", Self::JP => "jp",
            Self::KE => "ke", Self::KG => "kg", Self::KH => "kh", Self::KM => "km",
            Self::KR => "kr", Self::KW => "kw", Self::KY => "ky", Self::KZ => "kz",
            Self::LA => "la", Self::LB => "lb", Self::LC => "lc", Self::LK => "lk",
            Self::LS => "ls", Self::LT => "lt", Self::LU => "lu", Self::LV => "lv",
            Self::LY => "ly",
            Self::MA => "ma", Self::MD => "md", Self::ME => "me", Self::MG => "mg",
            Self::MK => "mk", Self::ML => "ml", Self::MM => "mm", Self::MN => "mn",
            Self::MO => "mo", Self::MQ => "mq", Self::MR => "mr", Self::MT => "mt",
            Self::MU => "mu", Self::MV => "mv", Self::MW => "mw", Self::MX => "mx",
            Self::MY => "my", Self::MZ => "mz",
            Self::NA => "na", Self::NE => "ne", Self::NG => "ng", Self::NI => "ni",
            Self::NL => "nl", Self::NO => "no", Self::NP => "np", Self::NZ => "nz",
            Self::OM => "om",
            Self::PA => "pa", Self::PE => "pe", Self::PG => "pg", Self::PH => "ph",
            Self::PK => "pk", Self::PL => "pl", Self::PR => "pr", Self::PS => "ps",
            Self::PT => "pt", Self::PY => "py",
            Self::QA => "qa",
            Self::RE => "re", Self::RO => "ro", Self::RS => "rs", Self::RU => "ru",
            Self::RW => "rw",
            Self::SA => "sa", Self::SC => "sc", Self::SE => "se", Self::SG => "sg",
            Self::SI => "si", Self::SK => "sk", Self::SL => "sl", Self::SN => "sn",
            Self::SO => "so", Self::SR => "sr", Self::ST => "st", Self::SV => "sv",
            Self::SX => "sx", Self::SY => "sy",
            Self::TG => "tg", Self::TH => "th", Self::TJ => "tj", Self::TM => "tm",
            Self::TN => "tn", Self::TR => "tr", Self::TT => "tt", Self::TW => "tw",
            Self::TZ => "tz",
            Self::UA => "ua", Self::UG => "ug", Self::US => "us", Self::UY => "uy",
            Self::UZ => "uz",
            Self::VC => "vc", Self::VE => "ve", Self::VI => "vi", Self::VN => "vn",
            Self::XK => "xk",
            Self::YE => "ye", Self::YT => "yt",
            Self::ZA => "za", Self::ZM => "zm", Self::ZW => "zw",
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_param_str_lowercase() {
        assert_eq!(Country::US.as_param_str(), "us");
        assert_eq!(Country::DE.as_param_str(), "de");
        assert_eq!(Country::NL.as_param_str(), "nl");
    }

    #[test]
    fn test_country_deserialize_uppercase() {
        let c: Country = serde_json::from_str(r#""US""#).unwrap();
        assert_eq!(c, Country::US);
    }


}
