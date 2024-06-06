package team07.airbnb.domain.booking.dto.request;

import org.springframework.lang.Nullable;

import java.time.LocalDate;

public record BookingRequestInfo(
        long accommodationId,
        @Nullable LocalDate checkIn,
        @Nullable LocalDate checkOut,
        @Nullable Integer headCount,
        long avgPrice
) {
}
