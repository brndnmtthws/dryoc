//! The wincode 0.6 schemas of the `Vec`-based Rustaceous boxes.

/// Implements `wincode::SchemaWrite` and `wincode::SchemaRead` for the box
/// type `$ty`, whose wire format is its listed fields, in order, each in the
/// wincode encoding of its wire type `$wire`.
///
/// Each field is written from `$to` (a `&$wire` computed from the source
/// value bound to `$src`) and rebuilt from the decoded `$wire` value bound to
/// `$val` by `$from`. `$ty` is then built by a struct literal of the listed
/// fields plus the `$extra` fields (such as `PhantomData` markers), which
/// carry no bytes; the literal must name every field of `$ty`.
macro_rules! impl_wincode_schema {
    (
        $ty:ty {
            $($field:ident: $wire:ty = ($src:ident => $to:expr, $val:ident => $from:expr)),+ $(,)?
        }
        $(extra { $($extra:ident: $extra_value:expr),+ $(,)? })?
    ) => {
        #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "wincode_0_6")))]
        // SAFETY: `write` writes exactly the listed fields, in order, each
        // through its wire type's own `SchemaWrite`, and `size_of` returns the
        // sum of those types' `size_of` for the same values, so it is exactly
        // the number of bytes `write` produces. `read` reads the same fields
        // in the same order through the same types' `SchemaRead`, and writes
        // `dst` once, after every field has decoded, with a struct literal
        // of the decoded fields (the compiler rejects a literal that misses a
        // field); on an error it returns without touching `dst`.
        unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for $ty {
            type Src = Self;

            fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
                let mut size = 0;
                $(
                    size += {
                        let $src = src;
                        <$wire as wincode::SchemaWrite<C>>::size_of($to)?
                    };
                )+
                Ok(size)
            }

            fn write(
                mut writer: impl wincode::io::Writer,
                src: &Self::Src,
            ) -> wincode::WriteResult<()> {
                $(
                    {
                        let $src = src;
                        <$wire as wincode::SchemaWrite<C>>::write(writer.by_ref(), $to)?;
                    }
                )+
                Ok(())
            }
        }

        #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "wincode_0_6")))]
        // SAFETY: see the `SchemaWrite` implementation above.
        unsafe impl<'de, C: wincode::config::Config> wincode::SchemaRead<'de, C> for $ty {
            type Dst = Self;

            fn read(
                mut reader: impl wincode::io::Reader<'de>,
                dst: &mut core::mem::MaybeUninit<Self::Dst>,
            ) -> wincode::ReadResult<()> {
                $(
                    let $field = {
                        let $val = <$wire as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
                        $from
                    };
                )+
                dst.write(Self {
                    $($field,)+
                    $($($extra: $extra_value,)+)?
                });
                Ok(())
            }
        }
    };
}
