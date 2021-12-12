using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthenticationApi.Entities
{
    public abstract class AuditedEntity
    {
        public long Id { get; set; }
        public DateTime CreationTime { get; set; }
        public long? CreatorUserId { get; set; }
        public DateTime? LastModificationTime { get; set; }
        public long? LastModifierUserId { get; set; }
        public long? DeleterUserId { get; set; }
        public DateTime? DeletionTime { get; set; }
        public bool IsDeleted { get; set; }
        public bool IsActive { get; set; }
        public string TimeStamp { get; set; }
        [NotMapped]
        public long Row { get; set; }
    }
}
