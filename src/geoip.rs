use std::{net::IpAddr, path::Path};

use anyhow::Context;
use maxminddb::{geoip2, Reader};
use tracing::{debug, warn};

use crate::config::GeoIpConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct GeoIpRecord {
    pub iso2: String,
    pub iso3: String,
    pub city_name: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug)]
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn open(config: &GeoIpConfig) -> anyhow::Result<Self> {
        let path = expand_home(&config.database);
        let reader = Reader::open_readfile(&path)
            .with_context(|| format!("failed to open GeoIP database {}", path.display()))?;
        Ok(Self { reader })
    }

    pub fn lookup(&self, addr: IpAddr) -> Option<GeoIpRecord> {
        match self.reader.lookup::<geoip2::City>(addr) {
            Ok(city) => {
                let iso2 = city.country.and_then(|country| country.iso_code)?;
                let iso3 = iso2_to_iso3(iso2)?;
                let city_name = city
                    .city
                    .and_then(|city| city.names)
                    .and_then(|names| names.get("en").copied())
                    .map(str::to_owned);
                let (latitude, longitude) = city
                    .location
                    .map(|location| (location.latitude, location.longitude))
                    .unwrap_or((None, None));
                Some(GeoIpRecord {
                    iso2: iso2.to_owned(),
                    iso3: iso3.to_owned(),
                    city_name,
                    latitude,
                    longitude,
                })
            }
            Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => None,
            Err(err) => {
                debug!(%addr, error = %err, "GeoIP lookup failed");
                None
            }
        }
    }
}

pub fn open(config: Option<&GeoIpConfig>) -> Option<GeoIp> {
    let config = config?;
    match GeoIp::open(config) {
        Ok(geoip) => {
            tracing::info!(database = %config.database, "loaded GeoIP database");
            Some(geoip)
        }
        Err(err) => {
            warn!(error = %err, "GeoIP disabled");
            None
        }
    }
}

fn expand_home(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    Path::new(path).to_path_buf()
}

fn iso2_to_iso3(iso2: &str) -> Option<&'static str> {
    Some(match iso2 {
        "AD" => "AND",
        "AE" => "ARE",
        "AF" => "AFG",
        "AG" => "ATG",
        "AI" => "AIA",
        "AL" => "ALB",
        "AM" => "ARM",
        "AO" => "AGO",
        "AQ" => "ATA",
        "AR" => "ARG",
        "AS" => "ASM",
        "AT" => "AUT",
        "AU" => "AUS",
        "AW" => "ABW",
        "AX" => "ALA",
        "AZ" => "AZE",
        "BA" => "BIH",
        "BB" => "BRB",
        "BD" => "BGD",
        "BE" => "BEL",
        "BF" => "BFA",
        "BG" => "BGR",
        "BH" => "BHR",
        "BI" => "BDI",
        "BJ" => "BEN",
        "BL" => "BLM",
        "BM" => "BMU",
        "BN" => "BRN",
        "BO" => "BOL",
        "BQ" => "BES",
        "BR" => "BRA",
        "BS" => "BHS",
        "BT" => "BTN",
        "BV" => "BVT",
        "BW" => "BWA",
        "BY" => "BLR",
        "BZ" => "BLZ",
        "CA" => "CAN",
        "CC" => "CCK",
        "CD" => "COD",
        "CF" => "CAF",
        "CG" => "COG",
        "CH" => "CHE",
        "CI" => "CIV",
        "CK" => "COK",
        "CL" => "CHL",
        "CM" => "CMR",
        "CN" => "CHN",
        "CO" => "COL",
        "CR" => "CRI",
        "CU" => "CUB",
        "CV" => "CPV",
        "CW" => "CUW",
        "CX" => "CXR",
        "CY" => "CYP",
        "CZ" => "CZE",
        "DE" => "DEU",
        "DJ" => "DJI",
        "DK" => "DNK",
        "DM" => "DMA",
        "DO" => "DOM",
        "DZ" => "DZA",
        "EC" => "ECU",
        "EE" => "EST",
        "EG" => "EGY",
        "EH" => "ESH",
        "ER" => "ERI",
        "ES" => "ESP",
        "ET" => "ETH",
        "FI" => "FIN",
        "FJ" => "FJI",
        "FK" => "FLK",
        "FM" => "FSM",
        "FO" => "FRO",
        "FR" => "FRA",
        "GA" => "GAB",
        "GB" => "GBR",
        "GD" => "GRD",
        "GE" => "GEO",
        "GF" => "GUF",
        "GG" => "GGY",
        "GH" => "GHA",
        "GI" => "GIB",
        "GL" => "GRL",
        "GM" => "GMB",
        "GN" => "GIN",
        "GP" => "GLP",
        "GQ" => "GNQ",
        "GR" => "GRC",
        "GS" => "SGS",
        "GT" => "GTM",
        "GU" => "GUM",
        "GW" => "GNB",
        "GY" => "GUY",
        "HK" => "HKG",
        "HM" => "HMD",
        "HN" => "HND",
        "HR" => "HRV",
        "HT" => "HTI",
        "HU" => "HUN",
        "ID" => "IDN",
        "IE" => "IRL",
        "IL" => "ISR",
        "IM" => "IMN",
        "IN" => "IND",
        "IO" => "IOT",
        "IQ" => "IRQ",
        "IR" => "IRN",
        "IS" => "ISL",
        "IT" => "ITA",
        "JE" => "JEY",
        "JM" => "JAM",
        "JO" => "JOR",
        "JP" => "JPN",
        "KE" => "KEN",
        "KG" => "KGZ",
        "KH" => "KHM",
        "KI" => "KIR",
        "KM" => "COM",
        "KN" => "KNA",
        "KP" => "PRK",
        "KR" => "KOR",
        "KW" => "KWT",
        "KY" => "CYM",
        "KZ" => "KAZ",
        "LA" => "LAO",
        "LB" => "LBN",
        "LC" => "LCA",
        "LI" => "LIE",
        "LK" => "LKA",
        "LR" => "LBR",
        "LS" => "LSO",
        "LT" => "LTU",
        "LU" => "LUX",
        "LV" => "LVA",
        "LY" => "LBY",
        "MA" => "MAR",
        "MC" => "MCO",
        "MD" => "MDA",
        "ME" => "MNE",
        "MF" => "MAF",
        "MG" => "MDG",
        "MH" => "MHL",
        "MK" => "MKD",
        "ML" => "MLI",
        "MM" => "MMR",
        "MN" => "MNG",
        "MO" => "MAC",
        "MP" => "MNP",
        "MQ" => "MTQ",
        "MR" => "MRT",
        "MS" => "MSR",
        "MT" => "MLT",
        "MU" => "MUS",
        "MV" => "MDV",
        "MW" => "MWI",
        "MX" => "MEX",
        "MY" => "MYS",
        "MZ" => "MOZ",
        "NA" => "NAM",
        "NC" => "NCL",
        "NE" => "NER",
        "NF" => "NFK",
        "NG" => "NGA",
        "NI" => "NIC",
        "NL" => "NLD",
        "NO" => "NOR",
        "NP" => "NPL",
        "NR" => "NRU",
        "NU" => "NIU",
        "NZ" => "NZL",
        "OM" => "OMN",
        "PA" => "PAN",
        "PE" => "PER",
        "PF" => "PYF",
        "PG" => "PNG",
        "PH" => "PHL",
        "PK" => "PAK",
        "PL" => "POL",
        "PM" => "SPM",
        "PN" => "PCN",
        "PR" => "PRI",
        "PS" => "PSE",
        "PT" => "PRT",
        "PW" => "PLW",
        "PY" => "PRY",
        "QA" => "QAT",
        "RE" => "REU",
        "RO" => "ROU",
        "RS" => "SRB",
        "RU" => "RUS",
        "RW" => "RWA",
        "SA" => "SAU",
        "SB" => "SLB",
        "SC" => "SYC",
        "SD" => "SDN",
        "SE" => "SWE",
        "SG" => "SGP",
        "SH" => "SHN",
        "SI" => "SVN",
        "SJ" => "SJM",
        "SK" => "SVK",
        "SL" => "SLE",
        "SM" => "SMR",
        "SN" => "SEN",
        "SO" => "SOM",
        "SR" => "SUR",
        "SS" => "SSD",
        "ST" => "STP",
        "SV" => "SLV",
        "SX" => "SXM",
        "SY" => "SYR",
        "SZ" => "SWZ",
        "TC" => "TCA",
        "TD" => "TCD",
        "TF" => "ATF",
        "TG" => "TGO",
        "TH" => "THA",
        "TJ" => "TJK",
        "TK" => "TKL",
        "TL" => "TLS",
        "TM" => "TKM",
        "TN" => "TUN",
        "TO" => "TON",
        "TR" => "TUR",
        "TT" => "TTO",
        "TV" => "TUV",
        "TW" => "TWN",
        "TZ" => "TZA",
        "UA" => "UKR",
        "UG" => "UGA",
        "UM" => "UMI",
        "US" => "USA",
        "UY" => "URY",
        "UZ" => "UZB",
        "VA" => "VAT",
        "VC" => "VCT",
        "VE" => "VEN",
        "VG" => "VGB",
        "VI" => "VIR",
        "VN" => "VNM",
        "VU" => "VUT",
        "WF" => "WLF",
        "WS" => "WSM",
        "YE" => "YEM",
        "YT" => "MYT",
        "ZA" => "ZAF",
        "ZM" => "ZMB",
        "ZW" => "ZWE",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_iso2_to_iso3() {
        assert_eq!(iso2_to_iso3("US"), Some("USA"));
        assert_eq!(iso2_to_iso3("DE"), Some("DEU"));
        assert_eq!(iso2_to_iso3("RS"), Some("SRB"));
        assert_eq!(iso2_to_iso3("ZZ"), None);
    }

    #[test]
    fn city_database_lookup_has_coordinates_when_available() {
        let path = expand_home("~/Downloads/GeoLite2-City.mmdb");
        if !path.exists() {
            return;
        }
        let geoip = GeoIp::open(&GeoIpConfig {
            database: path.display().to_string(),
        })
        .unwrap();
        let record = geoip.lookup("8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(record.iso2, "US");
        assert_eq!(record.iso3, "USA");
        assert!(record.latitude.is_some());
        assert!(record.longitude.is_some());
    }
}
