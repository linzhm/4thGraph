"""Lower weighted differences that share claims and weights across rows."""

from dataclasses import dataclass


@dataclass(frozen=True)
class WeightedDifferences:
    """An affine form with coefficients in a ring over the sample scalars."""

    bias: object
    weights: tuple

    @classmethod
    def lower(cls, claims, weights, columns, *, zero, add, multiply):
        """Factor sum(weight * (claim - sample[column])) before samples are read."""
        bias = zero
        by_column = {}
        for claim, weight, column in zip(claims, weights, columns, strict=True):
            bias = add(bias, multiply(weight, claim))
            by_column[column] = add(by_column[column], weight) if column in by_column else weight
        return cls(bias, tuple(by_column.items()))

    def evaluate(self, samples, *, scale, subtract):
        value = self.bias
        for column, weight in self.weights:
            value = subtract(value, scale(weight, samples[column]))
        return value
