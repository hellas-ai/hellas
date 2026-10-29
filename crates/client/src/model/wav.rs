//! Bounded WAV decoding and resampling for model requests.
use anyhow::{Result, ensure};
use std::io::Cursor;
pub const MAX_WAV_BYTES: usize = 32 << 20;

pub fn decode(bytes: &[u8]) -> Result<Vec<f32>> {
    ensure!(bytes.len() <= MAX_WAV_BYTES, "WAV exceeds byte limit");
    let mut reader = hound::WavReader::new(Cursor::new(bytes))?;
    let spec = reader.spec();
    ensure!(
        matches!(spec.channels, 1 | 2) && (8000..=192000).contains(&spec.sample_rate),
        "unsupported WAV channels or sample rate"
    );
    ensure!(
        reader.duration() > 0 && u64::from(reader.duration()) <= 30 * u64::from(spec.sample_rate),
        "WAV must contain at most 30 seconds of audio"
    );
    let samples: Vec<f32> = match spec.sample_format {
        hound::SampleFormat::Float => {
            ensure!(spec.bits_per_sample == 32, "expected 32-bit float WAV");
            reader.samples::<f32>().collect::<Result<_, _>>()?
        }
        hound::SampleFormat::Int => {
            ensure!(
                [8, 16, 24, 32].contains(&spec.bits_per_sample),
                "unsupported WAV bit depth"
            );
            let scale = 2f32.powi(i32::from(spec.bits_per_sample) - 1);
            reader
                .samples::<i32>()
                .map(|x| x.map(|v| v as f32 / scale))
                .collect::<Result<_, _>>()?
        }
    };
    ensure!(
        !samples.is_empty()
            && samples.len().is_multiple_of(spec.channels as usize)
            && samples.iter().all(|v| v.is_finite()),
        "invalid WAV samples"
    );
    let mono: Vec<_> = samples
        .chunks_exact(spec.channels as usize)
        .map(|frame| frame.iter().map(|x| *x / f32::from(spec.channels)).sum())
        .collect();
    ensure!(
        mono.len() as u64 <= 30 * u64::from(spec.sample_rate),
        "WAV exceeds 30 seconds"
    );
    if spec.sample_rate == 16000 {
        return Ok(mono);
    }
    Ok(resample(&mono, spec.sample_rate))
}

fn resample(samples: &[f32], rate: u32) -> Vec<f32> {
    let ratio = f64::from(rate) / 16000.;
    let cutoff = (1. / ratio).min(1.) * 0.94;
    let radius = (24. / cutoff).ceil() as isize;
    let length = (samples.len() as u64 * 16000).div_ceil(u64::from(rate)) as usize;
    (0..length)
        .map(|i| {
            let center = i as f64 * ratio;
            let mut total = 0.;
            let mut weight = 0.;
            for index in center.floor() as isize - radius..=center.floor() as isize + radius {
                let distance = center - index as f64;
                if distance.abs() >= radius as f64 {
                    continue;
                }
                let x = std::f64::consts::PI * distance * cutoff;
                let sinc = if x.abs() < 1e-12 { 1. } else { x.sin() / x };
                let window = 0.5 + 0.5 * (std::f64::consts::PI * distance / radius as f64).cos();
                let w = sinc * window;
                total +=
                    f64::from(samples[index.clamp(0, samples.len() as isize - 1) as usize]) * w;
                weight += w;
            }
            (total / weight) as f32
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wav_downmixes_and_keeps_16khz_samples_exact() {
        let mut bytes = Cursor::new(Vec::new());
        let mut writer = hound::WavWriter::new(
            &mut bytes,
            hound::WavSpec {
                channels: 2,
                sample_rate: 16000,
                bits_per_sample: 16,
                sample_format: hound::SampleFormat::Int,
            },
        )
        .unwrap();
        for sample in [16384i16, 0, -16384, 0] {
            writer.write_sample(sample).unwrap();
        }
        writer.finalize().unwrap();
        assert_eq!(decode(bytes.get_ref()).unwrap(), [0.25, -0.25]);
    }
    #[test]
    fn resampling_preserves_speech_band_and_rejects_aliases() {
        let tone = |hz: f64| {
            (0..4800)
                .map(|i| (std::f64::consts::TAU * hz * i as f64 / 48000.).sin() as f32)
                .collect::<Vec<_>>()
        };
        let pass = resample(&tone(1000.), 48000);
        let reject = resample(&tone(12000.), 48000);
        assert_eq!(pass.len(), 1600);
        let rms =
            |values: &[f32]| (values[100..1500].iter().map(|x| x * x).sum::<f32>() / 1400.).sqrt();
        assert!((rms(&pass) - 0.707).abs() < 0.01);
        assert!(rms(&reject) < 0.01);
    }
}
