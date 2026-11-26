use std::{path::Path, sync::Arc};

use common::event::{
    file_create::FileCreateEvent, image_load::ImageLoadEvent, process_create::ProcessCreateEvent,
    registry_set_value::RegistrySetValueEvent,
};
use rade::{Event as RadeEvent, Events, RadeEngine, Rule, Rules};

#[derive(Clone)]
pub struct Detector {
    engine: Arc<RadeEngine>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RuleHit {
    pub id: String,
    pub name: Option<String>,
}

impl Detector {
    pub fn from_rules_dir(dir: &Path) -> anyhow::Result<Self> {
        let rules = Rules::from_dir(dir).map_err(|e| anyhow::anyhow!("{e}"))?;
        Self::from_rules(rules)
    }

    #[cfg(test)]
    pub fn from_rule_yaml(yaml: &str) -> anyhow::Result<Self> {
        let rule = Rule::from_yaml(yaml).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut rules = Rules::default();
        rules.add_rule(rule);
        Self::from_rules(rules)
    }

    fn from_rules(rules: Rules) -> anyhow::Result<Self> {
        let mut engine = RadeEngine::from_rules(rules);
        engine.compile_rules();
        Ok(Self { engine: Arc::new(engine) })
    }

    pub fn evaluate(&self, event: RadeEvent) -> Vec<RuleHit> {
        let matches = match self.engine.eval_with_predicates(Events::new(vec![event])) {
            Ok(matches) => matches,
            Err(e) => {
                eprintln!("RADE evaluation failed: {e}");
                return Vec::new();
            },
        };

        let mut hits = Vec::new();
        for (_, matched_rules) in matches.iter() {
            for id in matched_rules.iter() {
                let name = self.engine.rules().get(id).and_then(Rule::name).map(str::to_string);
                hits.push(RuleHit { id: id.to_string(), name });
            }
        }
        hits
    }
}

fn file_stem(path: &str) -> Option<String> {
    Path::new(path).file_stem().and_then(|stem| stem.to_str()).map(str::to_string)
}

pub fn from_process_create(event: &ProcessCreateEvent) -> RadeEvent {
    let mut rade_event = RadeEvent::default();
    rade_event.add_string("event_type".to_string(), "process_create".to_string());
    rade_event.add_int("process_id".to_string(), i64::from(event.pid()));
    rade_event.add_int("parent_process_id".to_string(), i64::from(event.parent_id()));
    rade_event.add_int("create_time".to_string(), event.create_time() as i64);
    rade_event.add_string("Image".to_string(), event.path().to_string());
    rade_event.add_string("process_path".to_string(), event.path().to_string());
    rade_event.add_string("CommandLine".to_string(), event.command_line().to_string());
    rade_event.add_string("content".to_string(), event.command_line().to_string());
    if let Some(name) = file_stem(event.path()) {
        rade_event.add_string("process_name".to_string(), name);
    }
    rade_event
}

pub fn from_image_load(event: &ImageLoadEvent) -> RadeEvent {
    let mut rade_event = RadeEvent::default();
    rade_event.add_string("event_type".to_string(), "image_load".to_string());
    rade_event.add_int("process_id".to_string(), i64::from(event.pid()));
    rade_event.add_int("image_base".to_string(), event.image_base() as i64);
    rade_event.add_int("image_size".to_string(), event.image_size() as i64);
    rade_event.add_string("Image".to_string(), event.path().to_string());
    rade_event.add_string("image_path".to_string(), event.path().to_string());
    if let Some(name) = file_stem(event.path()) {
        rade_event.add_string("image_name".to_string(), name);
    }
    rade_event
}

pub fn from_file_create(event: &FileCreateEvent) -> RadeEvent {
    let path = event.get_path();
    let mut rade_event = RadeEvent::default();
    rade_event.add_string("event_type".to_string(), "file_create".to_string());
    rade_event.add_string("TargetFilename".to_string(), path.clone());
    rade_event.add_string("path".to_string(), path);
    rade_event
}

pub fn from_registry_set_value(event: &RegistrySetValueEvent) -> RadeEvent {
    let mut rade_event = RadeEvent::default();
    rade_event.add_string("event_type".to_string(), "registry_set_value".to_string());
    rade_event.add_int("process_id".to_string(), i64::from(event.pid()));
    let target_object = if event.value_name().is_empty() {
        event.key_name().to_string()
    } else {
        format!("{}\\{}", event.key_name(), event.value_name())
    };
    rade_event.add_string("TargetObject".to_string(), target_object);
    rade_event.add_string("key_name".to_string(), event.key_name().to_string());
    rade_event.add_string("value_name".to_string(), event.value_name().to_string());
    rade_event.add_int("data_type".to_string(), i64::from(event.data_type()));
    if let Some(data) = event.data_as_string() {
        if !data.is_empty() {
            rade_event.add_string("content".to_string(), data.clone());
            rade_event.add_string("data".to_string(), data);
        }
    }
    rade_event
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_POWERSHELL_RULE: &str = r#"
id: 11223344-5566-7788-99aa-bbccddeeff00
name: Base64 Encoded Command
condition: |
  process_name.to_lowercase() == 'powershell' && content.contains('-EncodedCommand')
"#;

    #[test]
    fn encoded_powershell_matches() {
        let detector = Detector::from_rule_yaml(ENCODED_POWERSHELL_RULE).unwrap();
        let event = ProcessCreateEvent::new(
            6276,
            2976,
            0x01db_0000_1234_5678,
            r"\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            None,
            "powershell.exe -EncodedCommand SGVsbG8gV29ybGQ=".to_string(),
        );

        let hits = detector.evaluate(from_process_create(&event));

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name.as_deref(), Some("Base64 Encoded Command"));
        assert_eq!(hits[0].id, "11223344-5566-7788-99aa-bbccddeeff00");
    }

    #[test]
    fn benign_process_does_not_match() {
        let detector = Detector::from_rule_yaml(ENCODED_POWERSHELL_RULE).unwrap();
        let event = ProcessCreateEvent::new(
            1111,
            500,
            0x01db_0000_1234_9999,
            r"\??\C:\Windows\System32\notepad.exe".to_string(),
            None,
            "notepad.exe C:\\notes.txt".to_string(),
        );

        assert!(detector.evaluate(from_process_create(&event)).is_empty());
    }

    #[test]
    fn event_without_rule_field_does_not_match_or_error() {
        let rule = r#"
id: 43025534-69e4-4e81-a78f-fad61111a7df
name: Command Line Contains Enc
condition: |
  CommandLine.contains('-enc')
"#;
        let detector = Detector::from_rule_yaml(rule).unwrap();
        let event = ImageLoadEvent::new(
            3784,
            140713424125952,
            196608,
            r"\Device\HarddiskVolume3\Windows\System32\ncrypt.dll".to_string(),
        );

        assert!(detector.evaluate(from_image_load(&event)).is_empty());
    }
}
