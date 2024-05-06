from dataclasses import dataclass, field
from typing import Union, List, Dict, Callable

import inflection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformationBase
from sigma.rule import SigmaDetectionItem


# TODO: remove it when the PR is merged into PySigma
@dataclass
class FieldFunctionTransformation(FieldMappingTransformationBase):
    """Map a field name to another using provided transformation function.
    You can overwrite transformation by providing explicit mapping for a field."""

    transform_func: Callable[[str], str]
    mapping: Dict[str, str] = field(default_factory=lambda: {})

    def _transform_name(self, f: str) -> str:
        return self.mapping.get(f, self.transform_func(f))

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        f = detection_item.field
        mapping = self._transform_name(f)
        if self.processing_item.match_field_name(self.pipeline, f):
            self.pipeline.field_mappings.add_mapping(f, mapping)
            detection_item.field = mapping
            self.processing_item_applied(detection_item)

    def apply_field_name(self, f: str) -> Union[str, List[str]]:
        return [self._transform_name(f)]


# Processing pipelines should be defined as functions that return a ProcessingPipeline object.
def snake_case() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Snake case names conversion pipeline",
        priority=20,  # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(  # Field mappings
                identifier="snake_case",
                transformation=FieldFunctionTransformation(transform_func=inflection.underscore),
            )
        ],
    )
