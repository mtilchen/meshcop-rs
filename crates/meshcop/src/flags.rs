//! Internal support for hand-rolled bit-flag newtypes.

macro_rules! impl_bitflag_newtype {
    (
        $(#[$type_meta:meta])*
        $visibility:vis struct $name:ident($bits:ty);
        constants {
            $($constant:item)*
        }
        methods {
            $(#[$from_meta:meta])*
            $from_bits:ident;
            $(#[$bits_meta:meta])*
            bits;
            $(#[$contains_meta:meta])*
            contains($other:ident: Self);
        }
        bit_ops;
    ) => {
        $(#[$type_meta])*
        $visibility struct $name($bits);

        impl $name {
            $($constant)*

            $(#[$from_meta])*
            pub const fn $from_bits(bits: $bits) -> Self {
                Self(bits)
            }

            $(#[$bits_meta])*
            pub const fn bits(self) -> $bits {
                self.0
            }

            $(#[$contains_meta])*
            pub const fn contains(self, $other: Self) -> bool {
                (self.0 & $other.0) == $other.0
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self::Output {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }
    };
    (
        $(#[$type_meta:meta])*
        $visibility:vis struct $name:ident($bits:ty);
        constants {
            $($constant:item)*
        }
        methods {
            $(#[$from_meta:meta])*
            $from_bits:ident;
            $(#[$bits_meta:meta])*
            bits;
            $(#[$contains_meta:meta])*
            contains($mask:ident: $mask_type:ty);
        }
    ) => {
        $(#[$type_meta])*
        $visibility struct $name($bits);

        impl $name {
            $($constant)*

            $(#[$from_meta])*
            pub const fn $from_bits(bits: $bits) -> Self {
                Self(bits)
            }

            $(#[$bits_meta])*
            pub const fn bits(self) -> $bits {
                self.0
            }

            $(#[$contains_meta])*
            pub const fn contains(self, $mask: $mask_type) -> bool {
                (self.0 & $mask) == $mask
            }
        }
    };
}
