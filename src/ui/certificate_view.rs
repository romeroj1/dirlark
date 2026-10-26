use super::{egui, output};
use crate::{
    certificates::{self, Part},
    model::Entry,
};
use base64::{Engine, engine::general_purpose::STANDARD};

pub(super) struct Viewer {
    dn: String,
    attribute: String,
    index: usize,
    part: usize,
    pub(super) tab: usize,
    decoded: Result<Vec<Part>, &'static str>,
    raw: String,
    standalone: Option<Entry>,
}
impl Viewer {
    pub fn new(entry: &Entry, attribute: &str, index: usize) -> Option<Self> {
        let value = entry.attrs.get(attribute)?.get(index)?;
        let kind = certificates::kind(attribute)?;
        let decoded =
            certificates::inspect(value, kind, x509_parser::time::ASN1Time::now().timestamp());
        Some(Self {
            dn: entry.dn.clone(),
            attribute: attribute.into(),
            index,
            part: 0,
            tab: 0,
            decoded,
            raw: if value.len() <= certificates::MAX_VALUE {
                STANDARD.encode(value)
            } else {
                String::new()
            },
            standalone: None,
        })
    }
    pub fn from_der(der: &[u8]) -> Option<Self> {
        if der.len() > 64 * 1024 {
            return None;
        }
        let entry = Entry {
            dn: "cn=server-certificate,dc=connection-security".into(),
            attrs: [("userCertificate".into(), vec![der.to_vec()])].into(),
        };
        let mut viewer = Self::new(&entry, "userCertificate", 0)?;
        viewer.standalone = Some(entry);
        Some(viewer)
    }
    /// Current-entry-only inspector. Never reads a directory or retains other entry data.
    pub fn show(&mut self, ctx: &egui::Context, entry: Option<&Entry>) -> bool {
        let standalone = self.standalone.clone();
        let Some(entry) = standalone
            .as_ref()
            .or_else(|| entry.filter(|e| e.dn == self.dn))
        else {
            return false;
        };
        let Some(values) = entry.attrs.get(&self.attribute) else {
            return false;
        };
        let mut open = true;
        egui::Window::new("Certificate viewer").id(egui::Id::unique("certificate-viewer"))
            .default_pos(egui::pos2(((ctx.content_rect().width()-780.0)*0.5).max(8.0),60.0))
            .open(&mut open).default_width(760.0).default_height(660.0).min_width(340.0)
            .resizable(true).vscroll(false).show(ctx, |ui| {
                ui.label("Decoded locally · no network requests");
                ui.small("Display only: signature, chain, revocation and hostname are not validated.");
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    ui.strong(format!("{} · Value {} of {}",self.attribute,self.index+1,values.len()));
                    let mut next=self.index;
                    if ui.add_enabled(self.index>0,egui::Button::new("Previous value")).clicked(){next-=1;}
                    if ui.add_enabled(self.index+1<values.len(),egui::Button::new("Next value")).clicked(){next+=1;}
                    if next!=self.index && let Some(viewer)=Self::new(entry,&self.attribute,next) {*self=viewer;}
                });
                ui.collapsing("Source entry", |ui|output::show(ui,"Entry DN",&self.dn));
                ui.horizontal_wrapped(|ui| {
                    for (index,label) in ["Overview","Extensions","Fingerprints / PEM","Raw LDAP"].iter().enumerate() {
                        ui.selectable_value(&mut self.tab,index,*label);
                    }
                });
                if let Ok(parts)=&self.decoded && parts.len()>1 {
                    egui::ComboBox::from_label("Certificate in this value").selected_text(&parts[self.part].label).show_ui(ui,|ui| {
                        for (index,part) in parts.iter().enumerate(){ui.selectable_value(&mut self.part,index,&part.label);}
                    });
                }
                ui.separator();
                egui::ScrollArea::vertical().id_salt(("certificate-content",self.tab,self.part,self.index))
                .max_height((ctx.content_rect().height()-310.0).clamp(120.0,460.0)).auto_shrink([false,false]).show(ui,|ui| {
                if self.tab == 3 {
                    if self.raw.is_empty() {output::show(ui,"Raw value notice","Too large to render here. Use the existing LDIF export for the raw entry.");}
                    else {output::show(ui,"Raw LDAP value · base64",&self.raw);}
                    return;
                }
                match &self.decoded {
                    Err(error)=>{output::show(ui,"Decode notice",error);},
                    Ok(parts)=> {
                        ui.heading(&parts[self.part].label);
                        match &parts[self.part].certificate {
                            Err(error)=>output::show(ui,"Decode notice",error),
                            Ok(cert)=> {
                                for (label,value) in &cert.fields {
                                    let tab = field_tab(label);
                                    if tab == self.tab { output::show(ui,label,value);ui.add_space(4.0); }
                                }
                                if self.tab == 2 {
                                    output::show(ui,"PEM certificate",&cert.pem);
                                    output::show(ui,"DER certificate · base64",&cert.der_base64);
                                }
                            }
                        }
                    }
                }
                });
                ui.collapsing("Raw LDAP value · base64", |ui| {
                    if self.raw.is_empty() {output::show(ui,"Raw value notice","Too large to render here. Use the existing LDIF export for the raw entry.");}
                    else {output::show(ui,"Raw LDAP value · base64",&self.raw);}
                });
            });
        open
    }
}

fn field_tab(label: &str) -> usize {
    if label.starts_with("SHA-") {
        2
    } else if label.starts_with("SAN ")
        || matches!(
            label,
            "Subject alternative names"
                | "Key usage"
                | "Extended key usage"
                | "Basic constraints"
                | "Authority key identifier"
                | "Subject key identifier"
        )
    {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(shape: &egui::epaint::Shape, output: &mut String, next: &mut Option<egui::Pos2>) {
        match shape {
            egui::epaint::Shape::Text(t) => {
                output.push_str(t.galley.text());
                if t.galley.text() == "Next value" {
                    *next = Some(t.pos + egui::vec2(5.0, 5.0));
                }
            }
            egui::epaint::Shape::Vec(shapes) => {
                for s in shapes {
                    text(s, output, next);
                }
            }
            _ => {}
        }
    }
    #[test]
    fn malformed_value_keeps_raw_view_and_next_value_navigation_works() {
        let entry = Entry {
            dn: "cn=synthetic,dc=test".into(),
            attrs: [(
                "userCertificate;binary".into(),
                vec![vec![0x30, 0], vec![0x30, 1, 0]],
            )]
            .into(),
        };
        let mut viewer = Viewer::new(&entry, "userCertificate;binary", 0).unwrap();
        let ctx = egui::Context::default();
        let mut next = None;
        let mut painted = String::new();
        let frame = |viewer: &mut Viewer, events| {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1280.0, 900.0),
                    )),
                    events,
                    ..Default::default()
                },
                |_ui| {
                    assert!(viewer.show(&ctx, Some(&entry)));
                },
            );
            let mut painted = String::new();
            let mut next = None;
            for clipped in &output.shapes {
                text(&clipped.shape, &mut painted, &mut next);
            }
            output.textures_delta.clear();
            (painted, next)
        };
        for _ in 0..3 {
            (painted, next) = frame(&mut viewer, vec![]);
        }
        assert!(painted.contains("Could not decode"));
        assert!(painted.contains("hostname are not validated"));
        assert!(painted.contains("Raw LDAP"));
        let pos = next.expect("Next value reachable without decoding success");
        for pressed in [true, false] {
            frame(
                &mut viewer,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        assert_eq!(viewer.index, 1);
        assert_eq!(viewer.raw, "MAEA");
        viewer.tab = 3;
        let (painted, _) = frame(&mut viewer, vec![]);
        assert!(painted.contains("Raw LDAP value · base64"));
        assert!(painted.contains("MAEA"));
        assert!(painted.contains("Copy"));
        let other = Entry {
            dn: "cn=other".into(),
            ..entry.clone()
        };
        assert!(!viewer.show(&ctx, Some(&other)));
    }
}
