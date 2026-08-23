const MAX_WINDOWS_COMMAND_LINE_UNITS: usize = 32_767;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputError {
    EmptyCommand,
    InteriorNul,
    CommandLineTooLong,
    InvalidEnvironmentName,
    EnvironmentTooLarge,
}

pub(crate) fn ensure_no_nul(value: &[u16]) -> Result<(), InputError> {
    if value.contains(&0) {
        return Err(InputError::InteriorNul);
    }
    Ok(())
}

pub(crate) fn quote_argument(argument: &[u16]) -> Result<Vec<u16>, InputError> {
    let quoted_length = quoted_argument_length(argument)?;
    if argument.is_empty() {
        return Ok(vec![u16::from(b'"'), u16::from(b'"')]);
    }

    let needs_quotes = argument.iter().any(|unit| {
        *unit == u16::from(b' ') || *unit == u16::from(b'\t') || *unit == u16::from(b'"')
    });
    if !needs_quotes {
        return Ok(argument.to_vec());
    }

    let mut quoted = Vec::with_capacity(quoted_length);
    quoted.push(u16::from(b'"'));

    let mut backslashes = 0usize;
    for &unit in argument {
        if unit == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }

        if unit == u16::from(b'"') {
            quoted.extend(std::iter::repeat_n(
                u16::from(b'\\'),
                backslashes.saturating_mul(2).saturating_add(1),
            ));
            quoted.push(unit);
        } else {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            quoted.push(unit);
        }
        backslashes = 0;
    }

    quoted.extend(std::iter::repeat_n(
        u16::from(b'\\'),
        backslashes.saturating_mul(2),
    ));
    quoted.push(u16::from(b'"'));
    Ok(quoted)
}

fn quoted_argument_length(argument: &[u16]) -> Result<usize, InputError> {
    ensure_no_nul(argument)?;
    if argument.is_empty() {
        return Ok(2);
    }

    let needs_quotes = argument.iter().any(|unit| {
        *unit == u16::from(b' ') || *unit == u16::from(b'\t') || *unit == u16::from(b'"')
    });
    if !needs_quotes {
        return Ok(argument.len());
    }

    let mut length = 2usize;
    let mut backslashes = 0usize;
    for &unit in argument {
        if unit == u16::from(b'\\') {
            backslashes = backslashes
                .checked_add(1)
                .ok_or(InputError::CommandLineTooLong)?;
            continue;
        }

        let emitted = if unit == u16::from(b'"') {
            backslashes
                .checked_mul(2)
                .and_then(|value| value.checked_add(2))
        } else {
            backslashes.checked_add(1)
        }
        .ok_or(InputError::CommandLineTooLong)?;
        length = length
            .checked_add(emitted)
            .ok_or(InputError::CommandLineTooLong)?;
        backslashes = 0;
    }
    length
        .checked_add(
            backslashes
                .checked_mul(2)
                .ok_or(InputError::CommandLineTooLong)?,
        )
        .ok_or(InputError::CommandLineTooLong)
}

pub(crate) fn build_command_line(
    command: &[u16],
    args: &[Vec<u16>],
) -> Result<Vec<u16>, InputError> {
    if command.is_empty() {
        return Err(InputError::EmptyCommand);
    }

    let mut command_line = Vec::new();
    for (index, argument) in std::iter::once(command)
        .chain(args.iter().map(Vec::as_slice))
        .enumerate()
    {
        let quoted_length = quoted_argument_length(argument)?;
        let separator_length = usize::from(index != 0);
        let terminated_length = command_line
            .len()
            .checked_add(separator_length)
            .and_then(|length| length.checked_add(quoted_length))
            .and_then(|length| length.checked_add(1))
            .ok_or(InputError::CommandLineTooLong)?;
        if terminated_length > MAX_WINDOWS_COMMAND_LINE_UNITS {
            return Err(InputError::CommandLineTooLong);
        }
        if index != 0 {
            command_line.push(u16::from(b' '));
        }
        command_line.extend(quote_argument(argument)?);
    }
    command_line.push(0);
    Ok(command_line)
}

pub(crate) fn validate_environment_entry(name: &[u16], value: &[u16]) -> Result<(), InputError> {
    ensure_no_nul(name)?;
    ensure_no_nul(value)?;
    if name.is_empty() || name.contains(&u16::from(b'=')) {
        return Err(InputError::InvalidEnvironmentName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_to_string(value: &[u16]) -> String {
        String::from_utf16(value).expect("test data should be valid UTF-16")
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn quotes_arguments_using_the_windows_crt_rules() {
        let cases = [
            ("", "\"\""),
            ("plain", "plain"),
            ("hello world", "\"hello world\""),
            ("hello\\world", "hello\\world"),
            ("hello\"world", "\"hello\\\"world\""),
            ("hello\\\"world", "\"hello\\\\\\\"world\""),
            ("hello world\\", "\"hello world\\\\\""),
        ];

        for (input, expected) in cases {
            assert_eq!(
                utf16_to_string(&quote_argument(&wide(input)).unwrap()),
                expected
            );
        }
    }

    #[test]
    fn builds_a_nul_terminated_command_line_with_argv_zero() {
        let command_line = build_command_line(
            &wide(r"C:\Program Files\Bun\bun.exe"),
            &[wide("run"), wide("a b")],
        )
        .unwrap();
        assert_eq!(command_line.last(), Some(&0));
        assert_eq!(
            utf16_to_string(&command_line[..command_line.len() - 1]),
            r#""C:\Program Files\Bun\bun.exe" run "a b""#
        );
    }

    #[test]
    fn rejects_nuls_empty_commands_and_oversized_command_lines() {
        assert_eq!(
            build_command_line(&[], &[]).unwrap_err(),
            InputError::EmptyCommand
        );
        assert_eq!(
            build_command_line(&wide("bun.exe"), &[wide("bad\0arg")]).unwrap_err(),
            InputError::InteriorNul
        );
        assert_eq!(
            build_command_line(
                &wide("bun.exe"),
                &[vec![u16::from(b'x'); MAX_WINDOWS_COMMAND_LINE_UNITS]],
            )
            .unwrap_err(),
            InputError::CommandLineTooLong
        );
    }

    #[test]
    fn validates_environment_names_and_values() {
        assert!(validate_environment_entry(&wide("PATH"), &wide(r"C:\bin")).is_ok());
        assert_eq!(
            validate_environment_entry(&[], &wide("value")).unwrap_err(),
            InputError::InvalidEnvironmentName
        );
        assert_eq!(
            validate_environment_entry(&wide("A=B"), &wide("value")).unwrap_err(),
            InputError::InvalidEnvironmentName
        );
        assert_eq!(
            validate_environment_entry(&wide("SAFE"), &wide("bad\0value")).unwrap_err(),
            InputError::InteriorNul
        );
    }

    #[test]
    fn preserves_unpaired_utf16_code_units() {
        let argument = [u16::from(b'a'), 0xD800, u16::from(b'b')];
        assert_eq!(quote_argument(&argument).unwrap(), argument);
    }
}
