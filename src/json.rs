//! Sérialisation JSON identique à `JSON.stringify` : nombres au format JavaScript
//! (`1.0` → `1`, `1e21` → `1e+21`), ordre des clés conservé, aucune espace.

use serde_json::Value;

pub fn stringify(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                out.push_str(&js_number(n.as_f64().unwrap_or(0.0)));
            }
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()));
                out.push(':');
                write(x, out);
            }
            out.push('}');
        }
    }
}

/// `Number.prototype.toString()` (ECMA-262 §6.1.6.1.20) ; `null` pour NaN et l'infini, comme JSON.
pub fn js_number(f: f64) -> String {
    if !f.is_finite() {
        return "null".into();
    }
    if f == 0.0 {
        return "0".into();
    }
    let neg = f < 0.0;
    let a = f.abs();
    // Représentation la plus courte : « d.ddde±x » → chiffres + exposant.
    let sci = format!("{:e}", a);
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;

    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{digits}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    if neg {
        format!("-{body}")
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_like_js() {
        assert_eq!(js_number(1.0), "1");
        assert_eq!(js_number(1.5), "1.5");
        assert_eq!(js_number(-0.0), "0");
        assert_eq!(js_number(100.0), "100");
        assert_eq!(js_number(1e21), "1e+21");
        assert_eq!(js_number(1e20), "100000000000000000000");
        assert_eq!(js_number(1e-7), "1e-7");
        assert_eq!(js_number(0.000001), "0.000001");
        assert_eq!(js_number(123456.789), "123456.789");
        assert_eq!(js_number(1.5e300), "1.5e+300");
        assert_eq!(js_number(f64::NAN), "null");
    }

    #[test]
    fn compact_and_ordered() {
        let v = json!({"b": 1, "a": [1.0, "x\n", null, true]});
        assert_eq!(stringify(&v), r#"{"b":1,"a":[1.0,"x\n",null,true]}"#.replace("1.0", "1"));
    }
}
